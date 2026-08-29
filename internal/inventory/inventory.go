package inventory

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
	"golang.org/x/sys/unix"
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
	limits                     Limits
	result                     Result
	retainedEncodedStringBytes int
	inventoryBudgetExhausted   bool
	rootMountID                uint64
	hook                       func(event, filePath string)
	seen                       map[string]observation
}

type observation struct {
	info       fs.FileInfo
	children   []string
	linkTarget string
	overflow   bool
	entryLimit int
	nested     bool
	omitted    bool
}

const maxInventoryEncodedStringBytes = 3 << 20

var ErrTargetChanged = errors.New("target changed during scan")

func Scan(target string, limits Limits) (Result, error) {
	return scan(target, limits, nil)
}

func scan(target string, limits Limits, hook func(event, filePath string)) (Result, error) {
	if limits.MaxFiles <= 0 || limits.MaxDepth <= 0 || limits.MaxFileBytes <= 0 || limits.MaxReadBytes <= 0 || limits.MaxBinaryFileBytes <= 0 || limits.MaxBinaryReadBytes <= 0 {
		return Result{}, errors.New("all inventory limits must be positive")
	}
	info, err := os.Lstat(target)
	if err != nil {
		return Result{}, fmt.Errorf("inspect target: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Result{}, errors.New("target must be a real directory, not a symbolic link")
	}
	root, err := os.Open(target)
	if err != nil {
		return Result{}, fmt.Errorf("open target root: %w", err)
	}
	defer root.Close()
	openedInfo, err := root.Stat()
	if err != nil || !sameFile(info, openedInfo) {
		return Result{}, errors.New("target identity changed while being opened")
	}
	mountID, err := descriptorMountID(root)
	if err != nil {
		return Result{}, fmt.Errorf("establish target mount boundary: %w", err)
	}

	w := &walker{limits: limits, result: Result{Contents: make(map[string][]byte)}, rootMountID: mountID, hook: hook, seen: make(map[string]observation)}
	w.seen["."] = observation{info: openedInfo}
	if err := w.walk(root, ".", 0); err != nil {
		return Result{}, err
	}
	rootAfter, err := root.Stat()
	if err != nil || !stableMetadata(openedInfo, rootAfter) {
		return Result{}, changed("target root metadata changed")
	}
	w.seen["."] = observationWithInfo(w.seen["."], rootAfter)
	w.callHook("initial-pass-complete", ".")
	if err := w.verifyTree(root, ".", 0); err != nil {
		return Result{}, err
	}
	sort.Slice(w.result.Files, func(i, j int) bool { return w.result.Files[i].Path < w.result.Files[j].Path })
	w.result.RootDigest, err = report.InventoryRootDigest(w.result.Files)
	if err != nil {
		return Result{}, fmt.Errorf("compute target inventory root digest: %w", err)
	}
	return w.result, nil
}

func (w *walker) walk(root *os.File, relative string, depth int) error {
	if depth > w.limits.MaxDepth {
		observed := w.seen[relative]
		observed.omitted = true
		w.seen[relative] = observed
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
		if w.inventoryBudgetExhausted {
			return nil
		}
		if len(w.result.Files) >= w.limits.MaxFiles {
			w.limit("max-files", "file-count limit reached; remaining entries were not inspected", displayPath(relative))
			return nil
		}
		name := entry.Name()
		childPath := name
		if relative != "." {
			childPath = path.Join(relative, name)
		}
		info, err := fileInfoAt(root, name)
		if err != nil {
			return changed("directory entry disappeared or changed before inspection: " + childPath)
		}
		file := report.File{Path: childPath, Mode: info.Mode().String(), Size: info.Size()}
		w.seen[childPath] = observation{info: info}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			file.Kind = "symlink"
			target, readErr := readlinkAt(root, name)
			if readErr != nil {
				w.scanError("readlink", readErr.Error(), childPath)
			} else {
				file.LinkTarget = target
				observed := w.seen[childPath]
				observed.linkTarget = target
				w.seen[childPath] = observed
			}
			if err := verifyPathStable(root, name, info, childPath); err != nil {
				return err
			}
			w.appendFile(file)
		case info.IsDir():
			file.Kind = "directory"
			if !w.appendFile(file) {
				return nil
			}
			child, nested, openErr := w.openChild(root, name, true)
			if nested {
				observed := w.seen[childPath]
				observed.nested = true
				w.seen[childPath] = observed
				file.SkipReason = "nested-mount"
				w.result.Files[len(w.result.Files)-1] = file
				w.limit("nested-mount", "directory crosses the selected plugin mount boundary and was not opened", childPath)
				continue
			}
			if openErr != nil {
				return changed("directory could not be pinned after enumeration: " + childPath)
			}
			openedInfo, statErr := child.Stat()
			if statErr != nil || !sameFile(info, openedInfo) {
				_ = child.Close()
				return changed("directory identity changed while it was opened: " + childPath)
			}
			w.callHook("directory-opened", childPath)
			if err := w.walk(child, childPath, depth+1); err != nil {
				_ = child.Close()
				return err
			}
			closedInfo, statErr := child.Stat()
			_ = child.Close()
			if statErr != nil || !stableMetadata(openedInfo, closedInfo) {
				return changed("directory metadata changed during traversal: " + childPath)
			}
			w.seen[childPath] = observationWithInfo(w.seen[childPath], closedInfo)
		case info.Mode().IsRegular():
			file.Kind = "regular"
			if isGitDatabasePath(childPath) {
				file.SkipReason = "git-internal-database"
				if err := verifyPathStable(root, name, info, childPath); err != nil {
					return err
				}
			} else if links, known := regularLinkCount(info); known && links > 1 {
				file.SkipReason = "multiple-hard-links"
				w.limit("multiple-hard-links", "regular file has multiple hard links and was not opened because another name may be outside the selected plugin", childPath)
				if err := verifyPathStable(root, name, info, childPath); err != nil {
					return err
				}
			} else {
				if err := w.inspectRegular(root, name, info, &file); err != nil {
					return err
				}
			}
			if !w.appendFile(file) {
				return nil
			}
		default:
			file.Kind = specialKind(info.Mode())
			if !w.appendFile(file) {
				return nil
			}
			w.limit("special-file", "special file was inventoried but not opened", childPath)
			if err := verifyPathStable(root, name, info, childPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyPathStable(root *os.File, name string, before fs.FileInfo, filePath string) error {
	after, err := fileInfoAt(root, name)
	if err != nil || !stableMetadata(before, after) {
		return changed("entry metadata changed during inspection: " + filePath)
	}
	return nil
}

func (w *walker) appendFile(file report.File) bool {
	values := []string{file.Path, file.Kind, file.Mode, file.SHA256, file.ContentType, file.LinkTarget, file.SkipReason}
	if binary := file.Binary; binary != nil {
		values = append(values, binary.Format, binary.Class, binary.ByteOrder, binary.Machine, binary.Type, binary.Interpreter)
		values = append(values, binary.Libraries...)
		values = append(values, binary.ImportedSymbols...)
		values = append(values, binary.ExtractedStrings...)
		values = append(values, binary.EmbeddedURLs...)
		values = append(values, binary.FileCapabilities...)
	}
	if archive := file.Archive; archive != nil {
		values = append(values, archive.Format)
		for _, entry := range archive.Entries {
			values = append(values, entry.Path, entry.Kind, entry.Mode, entry.LinkTarget)
		}
	}
	charge := 0
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil || len(encoded) > report.MaxHostileStringBytes || len(encoded) > maxInventoryEncodedStringBytes-charge {
			w.rollbackInspected(file)
			w.exhaustInventoryBudget(file.Path)
			return false
		}
		charge += len(encoded)
	}
	if charge > maxInventoryEncodedStringBytes-w.retainedEncodedStringBytes {
		w.rollbackInspected(file)
		w.exhaustInventoryBudget(file.Path)
		return false
	}
	w.retainedEncodedStringBytes += charge
	w.result.Files = append(w.result.Files, file)
	return true
}

func (w *walker) rollbackInspected(file report.File) {
	if !file.Inspected {
		return
	}
	delete(w.result.Contents, file.Path)
	if file.ContentType == "application/x-elf" {
		w.result.BinaryBytes -= file.Size
	} else {
		w.result.ReadBytes -= file.Size
	}
}

func (w *walker) exhaustInventoryBudget(filePath string) {
	if w.inventoryBudgetExhausted {
		return
	}
	w.inventoryBudgetExhausted = true
	if encoded, _ := json.Marshal(filePath); len(encoded) > report.MaxHostileStringBytes {
		filePath = ""
	}
	w.limit("result-production-limit", "inventory encoded-string production limit reached; this entry and remaining entries were not inventoried", filePath)
}

func readDirBounded(root *os.File, limit int) ([]fs.DirEntry, bool, error) {
	entries := make([]fs.DirEntry, 0, min(limit, 128))
	for {
		batchSize := min(128, limit+1-len(entries))
		batch, readErr := root.ReadDir(batchSize)
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

func (w *walker) reopenDirectory(directory *os.File) (*os.File, error) {
	fd, err := unix.Openat2(int(directory.Fd()), ".", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, err
	}
	result := os.NewFile(uintptr(fd), ".")
	mountID, err := descriptorMountID(result)
	if err != nil || mountID != w.rootMountID {
		_ = result.Close()
		return nil, errors.New("reopened directory crossed the selected plugin mount boundary")
	}
	return result, nil
}

func (w *walker) verifyTree(root *os.File, relative string, depth int) error {
	observedDirectory, ok := w.seen[relative]
	if !ok {
		return changed("verification encountered an unobserved directory: " + displayPath(relative))
	}
	currentInfo, err := root.Stat()
	if err != nil || !stableMetadata(observedDirectory.info, currentInfo) {
		return changed("directory changed before final verification: " + displayPath(relative))
	}
	if observedDirectory.omitted || depth > w.limits.MaxDepth {
		return nil
	}
	reader, err := w.reopenDirectory(root)
	if err != nil {
		return changed("directory could not be reopened during final verification: " + displayPath(relative))
	}
	entries, exceeded, readErr := readDirBounded(reader, observedDirectory.entryLimit)
	_ = reader.Close()
	if readErr != nil {
		return changed("directory could not be enumerated during final verification: " + displayPath(relative))
	}
	if observedDirectory.overflow {
		if !exceeded {
			return changed("overflowing directory membership changed before final verification: " + displayPath(relative))
		}
		return nil
	}
	if exceeded {
		return changed("directory gained entries before final verification: " + displayPath(relative))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	if len(entries) != len(observedDirectory.children) {
		return changed("directory membership changed before final verification: " + displayPath(relative))
	}
	for index, entry := range entries {
		if entry.Name() != observedDirectory.children[index] {
			return changed("directory membership changed before final verification: " + displayPath(relative))
		}
		childPath := entry.Name()
		if relative != "." {
			childPath = path.Join(relative, entry.Name())
		}
		observed, exists := w.seen[childPath]
		if !exists && w.inventoryBudgetExhausted {
			continue
		}
		if !exists {
			return changed("final verification encountered an unobserved entry: " + childPath)
		}
		info, statErr := fileInfoAt(root, entry.Name())
		if statErr != nil || !stableMetadata(observed.info, info) {
			return changed("entry changed before final verification: " + childPath)
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, linkErr := readlinkAt(root, entry.Name())
			if linkErr != nil || target != observed.linkTarget {
				return changed("symbolic-link target changed before final verification: " + childPath)
			}
		case info.IsDir() && !observed.nested:
			child, nested, openErr := w.openChild(root, entry.Name(), true)
			if openErr != nil || nested {
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

func isGitDatabasePath(name string) bool {
	clean := path.Clean(name)
	return strings.HasPrefix(clean, ".git/objects/") || strings.HasPrefix(clean, ".git/logs/")
}

func (w *walker) inspectRegular(root *os.File, name string, expected fs.FileInfo, out *report.File) error {
	f, nested, err := w.openChild(root, name, false)
	if nested {
		out.SkipReason = "nested-mount"
		w.limit("nested-mount", "file crosses the selected plugin mount boundary and was not opened", out.Path)
		return nil
	}
	if err != nil {
		w.scanError("open-file", err.Error(), out.Path)
		return changed("file could not be pinned after enumeration: " + out.Path)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameFile(expected, opened) || !opened.Mode().IsRegular() {
		return changed("file identity or type changed while it was opened: " + out.Path)
	}
	w.callHook("file-opened", out.Path)
	if links, known := regularLinkCount(opened); known && links > 1 {
		out.SkipReason = "multiple-hard-links"
		w.limit("multiple-hard-links", "regular file gained another hard link before content inspection and was not read", out.Path)
		return verifyDescriptorStable(f, opened, out.Path)
	}
	header := make([]byte, 4)
	_, headerErr := io.ReadFull(f, header)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		w.scanError("seek-file", err.Error(), out.Path)
		return verifyStableRead(f, opened, opened.Size(), out.Path)
	}
	if headerErr == nil && isELF(header) {
		if err := w.inspectELF(f, expected, out); err != nil {
			return err
		}
		return verifyStableRead(f, opened, opened.Size(), out.Path)
	}
	if expected.Size() > w.limits.MaxFileBytes {
		w.limit("max-file-bytes", "non-ELF file exceeds the individual source inspection limit", out.Path)
		return verifyStableRead(f, opened, opened.Size(), out.Path)
	}
	if w.result.ReadBytes+expected.Size() > w.limits.MaxReadBytes {
		w.limit("max-total-bytes", "total source-content inspection limit reached", out.Path)
		return verifyStableRead(f, opened, opened.Size(), out.Path)
	}
	data, err := io.ReadAll(io.LimitReader(f, w.limits.MaxFileBytes+1))
	if err != nil {
		w.scanError("read-file", err.Error(), out.Path)
		return verifyStableRead(f, opened, opened.Size(), out.Path)
	}
	if !stableRead(f, expected, int64(len(data))) {
		return changed("file identity, size, or timestamps changed while it was read: " + out.Path)
	}
	w.result.ReadBytes += int64(len(data))
	hash := sha256.Sum256(data)
	out.SHA256 = hex.EncodeToString(hash[:])
	out.ContentType = http.DetectContentType(data)
	out.Inspected = true
	w.recordArchive(data, out)
	w.result.Contents[out.Path] = data
	w.callHook("file-read", out.Path)
	return verifyStableRead(f, opened, int64(len(data)), out.Path)
}

func (w *walker) openChild(parent *os.File, name string, directory bool) (*os.File, bool, error) {
	flags := uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW)
	if directory {
		flags |= unix.O_DIRECTORY
	}
	how := &unix.OpenHow{Flags: flags, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV}
	fd, err := unix.Openat2(int(parent.Fd()), name, how)
	if errors.Is(err, unix.EXDEV) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), name)
	mountID, err := descriptorMountID(file)
	if err != nil || mountID != w.rootMountID {
		_ = file.Close()
		if err != nil {
			return nil, false, fmt.Errorf("verify child mount ID: %w", err)
		}
		return nil, true, nil
	}
	return file, false, nil
}

func descriptorMountID(file *os.File) (uint64, error) {
	var stat unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &stat); err != nil {
		return 0, err
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 || stat.Mnt_id == 0 {
		return 0, errors.New("mount ID is unavailable")
	}
	return stat.Mnt_id, nil
}

func readlinkAt(parent *os.File, name string) (string, error) {
	buffer := make([]byte, 4096)
	count, err := unix.Readlinkat(int(parent.Fd()), name, buffer)
	if err != nil {
		return "", err
	}
	if count == len(buffer) {
		return "", errors.New("symbolic-link target exceeds limit")
	}
	return string(buffer[:count]), nil
}

type descriptorFileInfo struct {
	name     string
	size     int64
	mode     os.FileMode
	modified time.Time
	stat     syscall.Stat_t
}

func (i descriptorFileInfo) Name() string       { return i.name }
func (i descriptorFileInfo) Size() int64        { return i.size }
func (i descriptorFileInfo) Mode() os.FileMode  { return i.mode }
func (i descriptorFileInfo) ModTime() time.Time { return i.modified }
func (i descriptorFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i descriptorFileInfo) Sys() any           { return &i.stat }

func fileInfoAt(parent *os.File, name string) (fs.FileInfo, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	mode := os.FileMode(stat.Mode & 0o777)
	if stat.Mode&unix.S_ISUID != 0 {
		mode |= os.ModeSetuid
	}
	if stat.Mode&unix.S_ISGID != 0 {
		mode |= os.ModeSetgid
	}
	if stat.Mode&unix.S_ISVTX != 0 {
		mode |= os.ModeSticky
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		mode |= os.ModeDir
	case unix.S_IFLNK:
		mode |= os.ModeSymlink
	case unix.S_IFIFO:
		mode |= os.ModeNamedPipe
	case unix.S_IFSOCK:
		mode |= os.ModeSocket
	case unix.S_IFBLK:
		mode |= os.ModeDevice
	case unix.S_IFCHR:
		mode |= os.ModeDevice | os.ModeCharDevice
	}
	systemStat := syscall.Stat_t{Dev: stat.Dev, Ino: stat.Ino, Nlink: stat.Nlink, Ctim: syscall.Timespec{Sec: stat.Ctim.Sec, Nsec: stat.Ctim.Nsec}}
	return descriptorFileInfo{name: name, size: stat.Size, mode: mode, modified: time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec), stat: systemStat}, nil
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
		return verifyStableRead(f, expected, expected.Size(), out.Path)
	}
	if !stableRead(f, expected, int64(len(data))) {
		return changed("ELF identity, size, or timestamps changed while it was read: " + out.Path)
	}
	w.recordELF(data, out)
	if out.Binary != nil {
		out.Binary.SetUID = expected.Mode()&os.ModeSetuid != 0
		out.Binary.SetGID = expected.Mode()&os.ModeSetgid != 0
		w.recordFileCapabilities(f, out)
	}
	w.callHook("file-read", out.Path)
	return nil
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
	if len(libraries) > report.MaxImportedLibraries {
		libraries = libraries[:report.MaxImportedLibraries]
		w.limit("result-production-limit", "ELF imported-library production limit reached; remaining names were not retained", out.Path)
	}
	symbols, _ := parsed.Symbols()
	imports, importsTruncated := importedSymbolNames(parsed)
	stringsFound, stringsTruncated := printableStrings(data)
	urls, urlsTruncated := embeddedURLs(stringsFound)
	if importsTruncated || stringsTruncated || urlsTruncated {
		w.limit("result-production-limit", "ELF imports, strings, or URL metadata reached a retained collection limit", out.Path)
	}
	out.Binary = &report.Binary{
		Format: "ELF", Class: parsed.Class.String(), ByteOrder: parsed.Data.String(), Machine: parsed.Machine.String(),
		Type: parsed.Type.String(), Interpreter: elfInterpreter(parsed), Libraries: nonNilStrings(libraries),
		ImportedSymbols: imports, ExtractedStrings: stringsFound, EmbeddedURLs: urls, FileCapabilities: []string{}, HasSymbols: len(symbols) > 0,
	}
}

func importedSymbolNames(parsed *elf.File) ([]string, bool) {
	symbols, err := parsed.DynamicSymbols()
	if err != nil {
		return []string{}, false
	}
	seen := make(map[string]struct{})
	for _, symbol := range symbols {
		if symbol.Section == elf.SHN_UNDEF && symbol.Name != "" {
			seen[symbol.Name] = struct{}{}
		}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	truncated := len(values) > report.MaxImportedSymbols
	if truncated {
		values = values[:report.MaxImportedSymbols]
	}
	return values, truncated
}

func printableStrings(data []byte) ([]string, bool) {
	values := make([]string, 0)
	seen := make(map[string]struct{})
	truncated := false
	for start := 0; start < len(data); {
		for start < len(data) && (data[start] < 0x20 || data[start] > 0x7e) {
			start++
		}
		end := start
		for end < len(data) && data[end] >= 0x20 && data[end] <= 0x7e {
			end++
		}
		if end-start >= 6 {
			value := string(data[start:end])
			if len(value) > report.MaxHostileStringBytes/2 {
				value = value[:report.MaxHostileStringBytes/2]
			}
			if _, exists := seen[value]; !exists {
				seen[value] = struct{}{}
				if len(values) < report.MaxExtractedStrings {
					values = append(values, value)
				} else {
					truncated = true
				}
			}
		}
		start = end + 1
	}
	sort.Strings(values)
	return values, truncated
}

func embeddedURLs(stringsFound []string) ([]string, bool) {
	values := make([]string, 0)
	seen := make(map[string]struct{})
	truncated := false
	for _, value := range stringsFound {
		for _, scheme := range []string{"https://", "http://", "ftp://", "ssh://"} {
			remaining := value
			for {
				index := strings.Index(remaining, scheme)
				if index < 0 {
					break
				}
				candidate := remaining[index:]
				if stop := strings.IndexAny(candidate, " \t\r\n\"'<>[](){}"); stop >= 0 {
					candidate = candidate[:stop]
				}
				if len(candidate) > len(scheme) {
					if _, exists := seen[candidate]; !exists {
						seen[candidate] = struct{}{}
						if len(values) < report.MaxEmbeddedURLs {
							values = append(values, candidate)
						} else {
							truncated = true
						}
					}
				}
				remaining = remaining[index+len(scheme):]
			}
		}
	}
	sort.Strings(values)
	return values, truncated
}

func (w *walker) recordFileCapabilities(f *os.File, out *report.File) {
	buffer := make([]byte, 256)
	count, err := unix.Fgetxattr(int(f.Fd()), "security.capability", buffer)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return
	}
	if err != nil {
		w.limit("elf-capability-metadata", "ELF file capability metadata could not be read: "+err.Error(), out.Path)
		return
	}
	capabilities, effective, ok := parseFileCapabilities(buffer[:count])
	if !ok {
		w.limit("elf-capability-metadata", "ELF file capability metadata used an unsupported or malformed encoding", out.Path)
		return
	}
	out.Binary.FileCapabilities = capabilities
	out.Binary.CapabilityEffective = effective
}

func parseFileCapabilities(data []byte) ([]string, bool, bool) {
	if len(data) < 12 {
		return []string{}, false, false
	}
	magic := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	revision := magic & 0xff000000
	words := 1
	if revision == 0x02000000 || revision == 0x03000000 {
		words = 2
	} else if revision != 0x01000000 {
		return []string{}, false, false
	}
	if len(data) < 4+words*8 {
		return []string{}, false, false
	}
	names := []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE"}
	values := make([]string, 0)
	for word := 0; word < words; word++ {
		offset := 4 + word*8
		bits := uint64(uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24)
		bits |= uint64(uint32(data[offset+4]) | uint32(data[offset+5])<<8 | uint32(data[offset+6])<<16 | uint32(data[offset+7])<<24)
		for bit := 0; bit < 32; bit++ {
			index := word*32 + bit
			if bits&(1<<bit) != 0 && index < len(names) {
				values = append(values, names[index])
			}
		}
	}
	return values, magic&1 != 0, true
}

func (w *walker) recordArchive(data []byte, out *report.File) {
	format := archiveFormat(data, out.Path)
	if format == "" {
		return
	}
	out.ContentType = archiveContentType(format)
	archive := &report.Archive{Format: format, Entries: []report.ArchiveEntry{}, InventoryComplete: false}
	out.Archive = archive
	switch format {
	case "zip":
		w.recordZIP(data, out.Path, archive)
	case "tar":
		w.recordTAR(data, out.Path, archive)
	default:
		w.limit("compressed-archive-inventory-unavailable", "The compressed archive was identified without decompression; member names and payload contents remain uninspected.", out.Path)
	}
}

func (w *walker) recordZIP(data []byte, filePath string, out *report.Archive) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		w.limit("archive-parse-error", "ZIP metadata parsing failed; no member content was extracted: "+err.Error(), filePath)
		return
	}
	complete := true
	for index, file := range reader.File {
		if index >= report.MaxArchiveEntries {
			complete = false
			w.limit("archive-entry-limit", "ZIP member inventory reached its retained-entry limit; remaining members were not retained.", filePath)
			break
		}
		if file.UncompressedSize64 > math.MaxInt64 || file.CompressedSize64 > math.MaxInt64 {
			complete = false
			w.limit("archive-size-overflow", "ZIP member size exceeds the report integer range; that member and later members were not retained.", filePath)
			break
		}
		entry, ok := archiveEntry(file.Name, zipEntryKind(file), file.Mode().String(), "", int64(file.UncompressedSize64), int64(file.CompressedSize64), file.Flags&1 != 0)
		if !ok || entry.Size > math.MaxInt64-out.RetainedUncompressedBytes {
			complete = false
			w.limit("archive-metadata-limit", "ZIP member metadata exceeds retained string or size limits; that member and later members were not retained.", filePath)
			break
		}
		out.Entries = append(out.Entries, entry)
		out.RetainedUncompressedBytes += entry.Size
	}
	out.InventoryComplete = complete
}

func (w *walker) recordTAR(data []byte, filePath string, out *report.Archive) {
	reader := tar.NewReader(bytes.NewReader(data))
	complete := true
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			complete = false
			w.limit("archive-parse-error", "TAR metadata parsing failed; no member content was extracted: "+err.Error(), filePath)
			break
		}
		if len(out.Entries) >= report.MaxArchiveEntries {
			complete = false
			w.limit("archive-entry-limit", "TAR member inventory reached its retained-entry limit; remaining members were not traversed.", filePath)
			break
		}
		entry, ok := archiveEntry(header.Name, tarEntryKind(header.Typeflag), header.FileInfo().Mode().String(), header.Linkname, header.Size, 0, false)
		if !ok || entry.Size > math.MaxInt64-out.RetainedUncompressedBytes {
			complete = false
			w.limit("archive-metadata-limit", "TAR member metadata exceeds retained string or size limits; that member and later members were not retained.", filePath)
			break
		}
		out.Entries = append(out.Entries, entry)
		out.RetainedUncompressedBytes += entry.Size
	}
	out.InventoryComplete = complete
}

func archiveEntry(name, kind, mode, link string, size, compressed int64, encrypted bool) (report.ArchiveEntry, bool) {
	if name == "" || kind == "" || size < 0 || compressed < 0 || !archiveStringFits(name) || !archiveStringFits(mode) || !archiveStringFits(link) {
		return report.ArchiveEntry{}, false
	}
	return report.ArchiveEntry{Path: name, Kind: kind, Mode: mode, LinkTarget: link, Size: size, CompressedSize: compressed, UnsafePath: unsafeArchivePath(name), Encrypted: encrypted}, true
}

func archiveStringFits(value string) bool {
	encoded, err := json.Marshal(value)
	return err == nil && len(encoded) <= report.MaxHostileStringBytes
}

func unsafeArchivePath(value string) bool {
	if strings.Contains(value, "\\") || path.IsAbs(value) {
		return true
	}
	clean := path.Clean(value)
	return clean == ".." || strings.HasPrefix(clean, "../")
}

func zipEntryKind(file *zip.File) string {
	mode := file.Mode()
	switch {
	case mode.IsDir():
		return "directory"
	case mode&os.ModeSymlink != 0:
		return "symlink"
	case mode.IsRegular():
		return "file"
	default:
		return "other"
	}
}

func tarEntryKind(flag byte) string {
	switch flag {
	case tar.TypeReg, tar.TypeRegA:
		return "file"
	case tar.TypeDir:
		return "directory"
	case tar.TypeSymlink:
		return "symlink"
	case tar.TypeLink:
		return "hardlink"
	default:
		return "other"
	}
}

func archiveFormat(data []byte, filePath string) string {
	switch {
	case len(data) >= 4 && bytes.Equal(data[:2], []byte{'P', 'K'}) && ((data[2] == 3 && data[3] == 4) || (data[2] == 5 && data[3] == 6) || (data[2] == 7 && data[3] == 8)):
		return "zip"
	case len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b:
		return "gzip"
	case len(data) >= 6 && bytes.Equal(data[:6], []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}):
		return "xz"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return "zstd"
	case len(data) >= 3 && bytes.Equal(data[:3], []byte{'B', 'Z', 'h'}):
		return "bzip2"
	case len(data) >= 262 && string(data[257:262]) == "ustar":
		return "tar"
	case strings.EqualFold(path.Ext(filePath), ".tar"):
		return "tar"
	}
	return ""
}

func archiveContentType(format string) string {
	switch format {
	case "zip":
		return "application/zip"
	case "tar":
		return "application/x-tar"
	case "gzip":
		return "application/gzip"
	case "xz":
		return "application/x-xz"
	case "zstd":
		return "application/zstd"
	case "bzip2":
		return "application/x-bzip2"
	}
	return "application/octet-stream"
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

func regularLinkCount(info fs.FileInfo) (uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Nlink), true
}

func stableRead(file *os.File, before fs.FileInfo, bytesRead int64) bool {
	after, err := file.Stat()
	if err != nil || !sameFile(before, after) || bytesRead != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return false
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	return !beforeOK || !afterOK || (beforeStat.Nlink == 1 && afterStat.Nlink == 1 && beforeStat.Ctim == afterStat.Ctim)
}

func stableMetadata(before, after fs.FileInfo) bool {
	if !sameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return false
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	return beforeOK && afterOK && beforeStat.Nlink == afterStat.Nlink && beforeStat.Ctim == afterStat.Ctim
}

func verifyStableRead(file *os.File, before fs.FileInfo, bytesRead int64, filePath string) error {
	if !stableRead(file, before, bytesRead) {
		return changed("file identity, size, or timestamps changed while it was read: " + filePath)
	}
	return nil
}

func verifyDescriptorStable(file *os.File, before fs.FileInfo, filePath string) error {
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
