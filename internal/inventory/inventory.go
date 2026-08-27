package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"sort"
	"syscall"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

type Limits struct {
	MaxFiles     int
	MaxDepth     int
	MaxFileBytes int64
	MaxReadBytes int64
}

func DefaultLimits() Limits {
	return Limits{
		MaxFiles:     10_000,
		MaxDepth:     32,
		MaxFileBytes: 2 << 20,
		MaxReadBytes: 32 << 20,
	}
}

type Result struct {
	Files       []report.File
	Limitations []report.Limitation
	Errors      []report.ScanError
	ReadBytes   int64
	RootDigest  string
}

type walker struct {
	limits Limits
	result Result
	digest hashWriter
}

type hashWriter struct{ parts [][]byte }

func (h *hashWriter) add(values ...string) {
	for _, value := range values {
		h.parts = append(h.parts, []byte(value), []byte{0})
	}
}

func (h *hashWriter) sum() string {
	s := sha256.New()
	for _, part := range h.parts {
		_, _ = s.Write(part)
	}
	return hex.EncodeToString(s.Sum(nil))
}

func Scan(target string, limits Limits) (Result, error) {
	if limits.MaxFiles <= 0 || limits.MaxDepth <= 0 || limits.MaxFileBytes <= 0 || limits.MaxReadBytes <= 0 {
		return Result{}, errors.New("all inventory limits must be positive")
	}
	info, err := os.Stat(target)
	if err != nil {
		return Result{}, fmt.Errorf("stat target: %w", err)
	}
	if !info.IsDir() {
		return Result{}, errors.New("target must be a directory")
	}
	root, err := os.OpenRoot(target)
	if err != nil {
		return Result{}, fmt.Errorf("open target root: %w", err)
	}
	defer root.Close()

	w := &walker{limits: limits}
	if err := w.walk(root, ".", 0); err != nil {
		return Result{}, err
	}
	sort.Slice(w.result.Files, func(i, j int) bool { return w.result.Files[i].Path < w.result.Files[j].Path })
	for _, file := range w.result.Files {
		w.digest.add(file.Path, file.Kind, file.Mode, fmt.Sprint(file.Size), file.SHA256, file.LinkTarget)
	}
	w.result.RootDigest = w.digest.sum()
	return w.result, nil
}

func (w *walker) walk(root *os.Root, relative string, depth int) error {
	if depth > w.limits.MaxDepth {
		w.limit("max-depth", "directory depth limit reached", displayPath(relative))
		return nil
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		w.scanError("read-directory", err.Error(), displayPath(relative))
		return nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if len(w.result.Files) >= w.limits.MaxFiles {
			w.limit("max-files", "file-count limit reached; remaining entries were not inspected", displayPath(relative))
			return nil
		}
		name := entry.Name()
		childPath := name
		if relative != "." {
			childPath = path.Join(relative, name)
		}
		info, err := root.Lstat(name)
		if err != nil {
			w.scanError("lstat", err.Error(), childPath)
			continue
		}
		file := report.File{Path: childPath, Mode: info.Mode().String(), Size: info.Size()}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			file.Kind = "symlink"
			target, readErr := root.Readlink(name)
			if readErr != nil {
				w.scanError("readlink", readErr.Error(), childPath)
			} else {
				file.LinkTarget = target
			}
			w.result.Files = append(w.result.Files, file)
		case info.IsDir():
			file.Kind = "directory"
			w.result.Files = append(w.result.Files, file)
			child, openErr := root.OpenRoot(name)
			if openErr != nil {
				w.scanError("open-directory", openErr.Error(), childPath)
				continue
			}
			openedInfo, statErr := child.Lstat(".")
			if statErr != nil || !sameFile(info, openedInfo) {
				_ = child.Close()
				w.scanError("changed-during-scan", "directory identity changed while it was opened", childPath)
				continue
			}
			_ = w.walk(child, childPath, depth+1)
			_ = child.Close()
		case info.Mode().IsRegular():
			file.Kind = "regular"
			w.inspectRegular(root, name, info, &file)
			w.result.Files = append(w.result.Files, file)
		default:
			file.Kind = specialKind(info.Mode())
			w.result.Files = append(w.result.Files, file)
			w.limit("special-file", "special file was inventoried but not opened", childPath)
		}
	}
	return nil
}

func (w *walker) inspectRegular(root *os.Root, name string, expected fs.FileInfo, out *report.File) {
	if expected.Size() > w.limits.MaxFileBytes {
		w.limit("max-file-bytes", "file exceeds the individual inspection limit", out.Path)
		return
	}
	if w.result.ReadBytes+expected.Size() > w.limits.MaxReadBytes {
		w.limit("max-total-bytes", "total content inspection limit reached", out.Path)
		return
	}
	f, err := root.Open(name)
	if err != nil {
		w.scanError("open-file", err.Error(), out.Path)
		return
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameFile(expected, opened) || !opened.Mode().IsRegular() {
		w.scanError("changed-during-scan", "file identity or type changed while it was opened", out.Path)
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, w.limits.MaxFileBytes+1))
	if err != nil {
		w.scanError("read-file", err.Error(), out.Path)
		return
	}
	if int64(len(data)) > w.limits.MaxFileBytes {
		w.limit("changed-during-scan", "file grew beyond the inspection limit while being read", out.Path)
		return
	}
	w.result.ReadBytes += int64(len(data))
	hash := sha256.Sum256(data)
	out.SHA256 = hex.EncodeToString(hash[:])
	out.ContentType = http.DetectContentType(data)
	out.Inspected = true
}

func (w *walker) limit(code, description, filePath string) {
	w.result.Limitations = append(w.result.Limitations, report.Limitation{Code: code, Description: description, Path: filePath})
}

func (w *walker) scanError(code, message, filePath string) {
	w.result.Errors = append(w.result.Errors, report.ScanError{Code: code, Message: message, Path: filePath})
}

func displayPath(relative string) string {
	if relative == "." {
		return ""
	}
	return relative
}

func specialKind(mode fs.FileMode) string {
	switch {
	case mode&os.ModeNamedPipe != 0:
		return "fifo"
	case mode&os.ModeSocket != 0:
		return "socket"
	case mode&os.ModeDevice != 0 && mode&os.ModeCharDevice != 0:
		return "character-device"
	case mode&os.ModeDevice != 0:
		return "block-device"
	default:
		return "special"
	}
}

func sameFile(a, b fs.FileInfo) bool {
	if a == nil || b == nil || a.Mode().Type() != b.Mode().Type() {
		return false
	}
	sa, okA := a.Sys().(*syscall.Stat_t)
	sb, okB := b.Sys().(*syscall.Stat_t)
	if okA && okB {
		return sa.Dev == sb.Dev && sa.Ino == sb.Ino
	}
	return os.SameFile(a, b)
}
