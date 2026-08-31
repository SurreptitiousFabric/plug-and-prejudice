package inventory

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

type Limits struct {
	MaxFiles           int
	MaxDepth           int
	MaxFileBytes       int64
	MaxReadBytes       int64
	MaxBinaryFileBytes int64
	MaxBinaryReadBytes int64
}

func DefaultLimits() Limits {
	return Limits{
		MaxFiles:           10_000,
		MaxDepth:           32,
		MaxFileBytes:       2 << 20,
		MaxReadBytes:       32 << 20,
		MaxBinaryFileBytes: 64 << 20,
		MaxBinaryReadBytes: 128 << 20,
	}
}

type Result struct {
	Files       []report.File
	Contents    map[string][]byte
	Limitations []report.Limitation
	Errors      []report.ScanError
	ReadBytes   int64
	BinaryBytes int64
	RootDigest  string
}

type walker struct {
	limits Limits
	result Result
	digest hashWriter
	hook   func(event, filePath string)
	seen   map[string]observation
}

type observation struct {
	info       fs.FileInfo
	children   []string
	linkTarget string
	overflow   bool
	entryLimit int
}

var ErrTargetChanged = errors.New("target changed during scan")

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
	return scan(target, limits, nil)
}

func scan(target string, limits Limits, hook func(event, filePath string)) (Result, error) {
	if limits.MaxFiles <= 0 || limits.MaxDepth <= 0 || limits.MaxFileBytes <= 0 || limits.MaxReadBytes <= 0 || limits.MaxBinaryFileBytes <= 0 || limits.MaxBinaryReadBytes <= 0 {
		return Result{}, errors.New("all inventory limits must be positive")
	}
	root, err := os.OpenRoot(target)
	if err != nil {
		return Result{}, fmt.Errorf("open target root: %w", err)
	}
	defer root.Close()
	rootInfo, err := root.Lstat(".")
	if err != nil || !rootInfo.IsDir() {
		return Result{}, errors.New("opened target root is not a directory")
	}

	w := &walker{limits: limits, result: Result{Contents: make(map[string][]byte)}, hook: hook, seen: make(map[string]observation)}
	w.seen["."] = observation{info: rootInfo}
	if err := w.walk(root, ".", 0); err != nil {
		return Result{}, err
	}
	rootAfter, err := root.Lstat(".")
	if err != nil || !stableMetadata(rootInfo, rootAfter) {
		return Result{}, changed("target root metadata changed")
	}
	w.seen["."] = observationWithInfo(w.seen["."], rootAfter)
	w.callHook("initial-pass-complete", ".")
	if err := w.verifyTree(root, ".", 0); err != nil {
		return Result{}, err
	}
	sort.Slice(w.result.Files, func(i, j int) bool { return w.result.Files[i].Path < w.result.Files[j].Path })
	for _, file := range w.result.Files {
		w.digest.add(file.Path, file.Kind, file.Mode, fmt.Sprint(file.Size), file.SHA256, file.LinkTarget, file.SkipReason)
	}
	w.result.RootDigest = w.digest.sum()
	return w.result, nil
}

func (w *walker) walk(root *os.Root, relative string, depth int) error {
	if depth > w.limits.MaxDepth {
		w.limit("max-depth", "directory depth limit reached", displayPath(relative))
		return nil
	}
	remaining := w.limits.MaxFiles - len(w.result.Files)
	entries, exceeded, err := readDirBounded(root, remaining)
	if err != nil {
		return fmt.Errorf("read directory %q: %w", displayPath(relative), err)
	}
	current := w.seen[relative]
	current.entryLimit = remaining
	current.overflow = exceeded
	if exceeded {
		w.seen[relative] = current
		w.limit("max-files", "directory entry count exceeds the remaining file-count budget; this directory was not inventoried", displayPath(relative))
		return nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	current.children = make([]string, len(entries))
	for index, entry := range entries {
		current.children[index] = entry.Name()
	}
	w.seen[relative] = current
	for _, entry := range entries {
		name := entry.Name()
		childPath := name
		if relative != "." {
			childPath = path.Join(relative, name)
		}
		info, err := root.Lstat(name)
		if err != nil {
			return changed("directory entry disappeared or changed before inspection: " + childPath)
		}
		file := report.File{Path: childPath, Mode: info.Mode().String(), Size: info.Size()}
		w.seen[childPath] = observation{info: info}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			file.Kind = "symlink"
			target, readErr := root.Readlink(name)
			if readErr != nil {
				w.scanError("readlink", readErr.Error(), childPath)
			} else {
				file.LinkTarget = target
				observed := w.seen[childPath]
				observed.linkTarget = target
				w.seen[childPath] = observed
			}
			if verifyErr := verifyPathStable(root, name, info, childPath); verifyErr != nil {
				return verifyErr
			}
			w.result.Files = append(w.result.Files, file)
		case info.IsDir():
			file.Kind = "directory"
			w.result.Files = append(w.result.Files, file)
			child, openErr := root.OpenRoot(name)
			if openErr != nil {
				return changed("directory could not be pinned after enumeration: " + childPath)
			}
			openedInfo, statErr := child.Lstat(".")
			if statErr != nil || !sameFile(info, openedInfo) {
				_ = child.Close()
				return changed("directory identity changed while it was opened: " + childPath)
			}
			w.callHook("directory-opened", childPath)
			if walkErr := w.walk(child, childPath, depth+1); walkErr != nil {
				_ = child.Close()
				return walkErr
			}
			closedInfo, statErr := child.Lstat(".")
			_ = child.Close()
			if statErr != nil || !stableMetadata(openedInfo, closedInfo) {
				return changed("directory metadata changed during traversal: " + childPath)
			}
			w.seen[childPath] = observationWithInfo(w.seen[childPath], closedInfo)
		case info.Mode().IsRegular():
			file.Kind = "regular"
			if isGitDatabasePath(childPath) {
				file.SkipReason = "git-internal-database"
				if verifyErr := verifyPathStable(root, name, info, childPath); verifyErr != nil {
					return verifyErr
				}
			} else {
				if inspectErr := w.inspectRegular(root, name, info, &file); inspectErr != nil {
					return inspectErr
				}
			}
			w.result.Files = append(w.result.Files, file)
		default:
			file.Kind = specialKind(info.Mode())
			w.result.Files = append(w.result.Files, file)
			w.limit("special-file", "special file was inventoried but not opened", childPath)
			if verifyErr := verifyPathStable(root, name, info, childPath); verifyErr != nil {
				return verifyErr
			}
		}
	}
	return nil
}

func readDirBounded(root *os.Root, limit int) ([]fs.DirEntry, bool, error) {
	if limit < 0 {
		limit = 0
	}
	directory, err := root.Open(".")
	if err != nil {
		return nil, false, err
	}
	defer directory.Close()
	entries := make([]fs.DirEntry, 0, min(limit, 128))
	for {
		batch, readErr := directory.ReadDir(min(128, limit+1-len(entries)))
		entries = append(entries, batch...)
		if len(entries) > limit {
			return nil, true, nil
		}
		if errors.Is(readErr, io.EOF) {
			return entries, false, nil
		}
		if readErr != nil {
			return nil, false, readErr
		}
	}
}

func observationWithInfo(value observation, info fs.FileInfo) observation {
	value.info = info
	return value
}

func (w *walker) verifyTree(root *os.Root, relative string, depth int) error {
	if depth > w.limits.MaxDepth {
		return nil
	}
	directoryObservation, ok := w.seen[relative]
	if !ok {
		return changed("verification encountered an unobserved directory: " + displayPath(relative))
	}
	currentInfo, err := root.Lstat(".")
	if err != nil || !stableMetadata(directoryObservation.info, currentInfo) {
		return changed("directory changed before final verification: " + displayPath(relative))
	}
	entries, exceeded, err := readDirBounded(root, directoryObservation.entryLimit)
	if err != nil {
		return changed("directory could not be enumerated during final verification: " + displayPath(relative))
	}
	if directoryObservation.overflow {
		if !exceeded {
			return changed("overflowing directory membership changed before final verification: " + displayPath(relative))
		}
		return nil
	}
	if exceeded {
		return changed("directory gained entries before final verification: " + displayPath(relative))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	if len(entries) != len(directoryObservation.children) {
		return changed("directory membership changed before final verification: " + displayPath(relative))
	}
	for index, entry := range entries {
		if entry.Name() != directoryObservation.children[index] {
			return changed("directory membership changed before final verification: " + displayPath(relative))
		}
		childPath := entry.Name()
		if relative != "." {
			childPath = path.Join(relative, entry.Name())
		}
		observed, exists := w.seen[childPath]
		if !exists {
			return changed("final verification encountered an unobserved entry: " + childPath)
		}
		info, statErr := root.Lstat(entry.Name())
		if statErr != nil || !stableMetadata(observed.info, info) {
			return changed("entry changed before final verification: " + childPath)
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, readErr := root.Readlink(entry.Name())
			if readErr != nil || target != observed.linkTarget {
				return changed("symbolic-link target changed before final verification: " + childPath)
			}
		case info.IsDir():
			child, openErr := root.OpenRoot(entry.Name())
			if openErr != nil {
				return changed("directory could not be reopened during final verification: " + childPath)
			}
			verifyErr := w.verifyTree(child, childPath, depth+1)
			_ = child.Close()
			if verifyErr != nil {
				return verifyErr
			}
		}
	}
	return nil
}

func verifyPathStable(root *os.Root, name string, before fs.FileInfo, filePath string) error {
	after, err := root.Lstat(name)
	if err != nil || !stableMetadata(before, after) {
		return changed("entry metadata changed during inspection: " + filePath)
	}
	return nil
}

func isGitDatabasePath(name string) bool {
	clean := path.Clean(name)
	return strings.HasPrefix(clean, ".git/objects/") || strings.HasPrefix(clean, ".git/logs/")
}

func (w *walker) inspectRegular(root *os.Root, name string, expected fs.FileInfo, out *report.File) error {
	f, err := root.Open(name)
	if err != nil {
		return changed("file could not be pinned after enumeration: " + out.Path)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameFile(expected, opened) || !opened.Mode().IsRegular() {
		return changed("file identity or type changed while it was opened: " + out.Path)
	}
	w.callHook("file-opened", out.Path)
	header := make([]byte, 4)
	_, headerErr := io.ReadFull(f, header)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		w.scanError("seek-file", err.Error(), out.Path)
		return w.verifyRegularStable(f, opened, out.Path)
	}
	if headerErr == nil && isELF(header) {
		if err := w.inspectELF(f, expected, out); err != nil {
			return err
		}
		return w.verifyRegularStable(f, opened, out.Path)
	}
	if expected.Size() > w.limits.MaxFileBytes {
		w.limit("max-file-bytes", "non-ELF file exceeds the individual source inspection limit", out.Path)
		return w.verifyRegularStable(f, opened, out.Path)
	}
	if w.result.ReadBytes+expected.Size() > w.limits.MaxReadBytes {
		w.limit("max-total-bytes", "total source-content inspection limit reached", out.Path)
		return w.verifyRegularStable(f, opened, out.Path)
	}
	data, err := io.ReadAll(io.LimitReader(f, w.limits.MaxFileBytes+1))
	if err != nil {
		w.scanError("read-file", err.Error(), out.Path)
		return w.verifyRegularStable(f, opened, out.Path)
	}
	if int64(len(data)) > w.limits.MaxFileBytes {
		w.limit("changed-during-scan", "file grew beyond the inspection limit while being read", out.Path)
		return changed("file grew while being read: " + out.Path)
	}
	w.result.ReadBytes += int64(len(data))
	hash := sha256.Sum256(data)
	out.SHA256 = hex.EncodeToString(hash[:])
	out.ContentType = http.DetectContentType(data)
	out.Inspected = true
	w.result.Contents[out.Path] = data
	w.callHook("file-read", out.Path)
	return w.verifyRegularStable(f, opened, out.Path)
}

func (w *walker) inspectELF(f *os.File, expected fs.FileInfo, out *report.File) error {
	if expected.Size() > w.limits.MaxBinaryFileBytes {
		w.limit("max-binary-file-bytes", "ELF file exceeds the individual binary inspection limit", out.Path)
		return nil
	}
	if w.result.BinaryBytes+expected.Size() > w.limits.MaxBinaryReadBytes {
		w.limit("max-binary-total-bytes", "total ELF inspection limit reached", out.Path)
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(f, w.limits.MaxBinaryFileBytes+1))
	if err != nil {
		w.scanError("read-binary", err.Error(), out.Path)
		return w.verifyRegularStable(f, expected, out.Path)
	}
	if int64(len(data)) != expected.Size() {
		w.scanError("changed-during-scan", "ELF size changed while it was read", out.Path)
		return changed("ELF size changed while it was read: " + out.Path)
	}
	w.recordELF(data, out)
	w.callHook("file-read", out.Path)
	return nil
}

func (w *walker) verifyRegularStable(file *os.File, before fs.FileInfo, filePath string) error {
	after, err := file.Stat()
	if err != nil || !stableMetadata(before, after) {
		return changed("file metadata changed during inspection: " + filePath)
	}
	return nil
}

func (w *walker) callHook(event, filePath string) {
	if w.hook != nil {
		w.hook(event, filePath)
	}
}

func changed(message string) error {
	return fmt.Errorf("%w: %s", ErrTargetChanged, message)
}

func (w *walker) recordELF(data []byte, out *report.File) {
	w.result.BinaryBytes += int64(len(data))
	hash := sha256.Sum256(data)
	out.SHA256 = hex.EncodeToString(hash[:])
	out.ContentType = "application/x-elf"
	out.Inspected = true
	parsed, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		w.limit("elf-parse-error", "ELF header was recognized but metadata parsing failed: "+err.Error(), out.Path)
		return
	}
	defer parsed.Close()
	libraries, err := parsed.ImportedLibraries()
	if err != nil {
		libraries = []string{}
	}
	sort.Strings(libraries)
	symbols, _ := parsed.Symbols()
	out.Binary = &report.Binary{
		Format: "ELF", Class: parsed.Class.String(), ByteOrder: parsed.Data.String(), Machine: parsed.Machine.String(),
		Type: parsed.Type.String(), Interpreter: elfInterpreter(parsed), Libraries: nonNilStrings(libraries), HasSymbols: len(symbols) > 0,
	}
}

func elfInterpreter(file *elf.File) string {
	for _, program := range file.Progs {
		if program.Type != elf.PT_INTERP || program.Filesz == 0 || program.Filesz > 4096 {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(program.Open(), 4096))
		if err == nil {
			return strings.TrimRight(string(data), "\x00")
		}
	}
	return ""
}

func isELF(data []byte) bool {
	return len(data) >= 4 && bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'})
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
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

func stableMetadata(a, b fs.FileInfo) bool {
	if !sameFile(a, b) || a.Mode() != b.Mode() || a.Size() != b.Size() {
		return false
	}
	sa, okA := a.Sys().(*syscall.Stat_t)
	sb, okB := b.Sys().(*syscall.Stat_t)
	if !okA || !okB {
		return false
	}
	return sa.Nlink == sb.Nlink && sa.Mtim == sb.Mtim && sa.Ctim == sb.Ctim
}
