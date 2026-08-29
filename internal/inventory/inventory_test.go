package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestScanFailsClosedWhenFileMutatesDuringRead(t *testing.T) {
	target := t.TempDir()
	file := filepath.Join(target, "mutable.js")
	mustWrite(t, file, "const value = 'before';")
	_, err := scan(target, DefaultLimits(), func(event, filePath string) {
		if event == "file-read" && filePath == "mutable.js" {
			mustWrite(t, file, "const value = 'after!';")
		}
	})
	if !errors.Is(err, ErrTargetChanged) {
		t.Fatalf("mutation result = %v, want ErrTargetChanged", err)
	}
}

func TestScanFailsClosedWhenPinnedFilePathIsReplaced(t *testing.T) {
	target := t.TempDir()
	file := filepath.Join(target, "mutable.js")
	mustWrite(t, file, "original")
	_, err := scan(target, DefaultLimits(), func(event, filePath string) {
		if event == "file-opened" && filePath == "mutable.js" {
			replacement := filepath.Join(target, "replacement")
			mustWrite(t, replacement, "replacement")
			if renameErr := os.Rename(replacement, file); renameErr != nil {
				t.Fatal(renameErr)
			}
		}
	})
	if !errors.Is(err, ErrTargetChanged) {
		t.Fatalf("replacement result = %v, want ErrTargetChanged", err)
	}
}

func TestScanFailsClosedWhenIntermediateDirectoryIsReplaced(t *testing.T) {
	target := t.TempDir()
	directory := filepath.Join(target, "nested")
	mustWrite(t, filepath.Join(directory, "file"), "original")
	_, err := scan(target, DefaultLimits(), func(event, filePath string) {
		if event == "directory-opened" && filePath == "nested" {
			moved := filepath.Join(target, "moved")
			if renameErr := os.Rename(directory, moved); renameErr != nil {
				t.Fatal(renameErr)
			}
			if mkdirErr := os.Mkdir(directory, 0o700); mkdirErr != nil {
				t.Fatal(mkdirErr)
			}
		}
	})
	if !errors.Is(err, ErrTargetChanged) {
		t.Fatalf("directory replacement result = %v, want ErrTargetChanged", err)
	}
}

func TestScanInventoriesRegularFilesWithoutFollowingSymlinks(t *testing.T) {
	target := t.TempDir()
	outside := t.TempDir()
	mustWrite(t, filepath.Join(target, "manifest.json"), `{"schemaVersion":1}`)
	mustWrite(t, filepath.Join(outside, "secret"), "must not be read")
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(target, "escape")); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(target, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 2 {
		t.Fatalf("files = %d, want 2", len(result.Files))
	}
	files := byPath(result)
	if files["escape"].Kind != "symlink" || files["escape"].Inspected {
		t.Fatalf("symlink was not safely inventoried: %#v", files["escape"])
	}
	if files["escape"].SHA256 != "" {
		t.Fatal("symlink unexpectedly has a content hash")
	}
	if !files["manifest.json"].Inspected || files["manifest.json"].SHA256 == "" {
		t.Fatalf("regular file not inspected: %#v", files["manifest.json"])
	}
}

func TestScanStopsAtFileCountLimit(t *testing.T) {
	target := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		mustWrite(t, filepath.Join(target, name), name)
	}
	limits := DefaultLimits()
	limits.MaxFiles = 2
	result, err := Scan(target, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 2 {
		t.Fatalf("files = %d, want 2", len(result.Files))
	}
	if !hasLimitation(result, "max-files") {
		t.Fatal("missing max-files limitation")
	}
}

func TestScanSkipsOversizeContent(t *testing.T) {
	target := t.TempDir()
	mustWrite(t, filepath.Join(target, "large"), strings.Repeat("x", 17))
	limits := DefaultLimits()
	limits.MaxFileBytes = 16
	result, err := Scan(target, limits)
	if err != nil {
		t.Fatal(err)
	}
	file := byPath(result)["large"]
	if file.Inspected || file.SHA256 != "" {
		t.Fatalf("oversize file was inspected: %#v", file)
	}
	if !hasLimitation(result, "max-file-bytes") {
		t.Fatal("missing max-file-bytes limitation")
	}
}

func TestScanRecordsFIFOWithoutOpeningIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("FIFO test requires Unix")
	}
	target := t.TempDir()
	fifo := filepath.Join(target, "hostile-pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Scan(target, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if byPath(result)["hostile-pipe"].Kind != "fifo" {
		t.Fatal("unexpected inventory kind")
	}
	if !hasLimitation(result, "special-file") {
		t.Fatal("missing special-file limitation")
	}
}

func TestScanRejectsInvalidLimits(t *testing.T) {
	_, err := Scan(t.TempDir(), Limits{})
	if err == nil {
		t.Fatal("Scan accepted zero limits")
	}
}

func TestScanDoesNotSpendSourceBudgetOnGitObjectDatabase(t *testing.T) {
	target := t.TempDir()
	mustWrite(t, filepath.Join(target, ".git", "objects", "pack", "large.pack"), strings.Repeat("x", 32))
	limits := DefaultLimits()
	limits.MaxFileBytes = 8
	result, err := Scan(target, limits)
	if err != nil {
		t.Fatal(err)
	}
	file := byPath(result)[".git/objects/pack/large.pack"]
	if file.Inspected || file.SkipReason != "git-internal-database" {
		t.Fatalf("Git database file was not explicitly skipped: %#v", file)
	}
	if hasLimitation(result, "max-file-bytes") {
		t.Fatalf("Git database consumed source-analysis limit: %#v", result.Limitations)
	}
}

func TestScanHashesAndDescribesELFWithoutAddingItToSourceContents(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	name := filepath.Join(target, "helper")
	if err := os.WriteFile(name, data, 0o700); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxFileBytes = 16
	limits.MaxBinaryFileBytes = int64(len(data)) + 1
	limits.MaxBinaryReadBytes = int64(len(data)) + 1
	result, err := Scan(target, limits)
	if err != nil {
		t.Fatal(err)
	}
	file := byPath(result)["helper"]
	if file.Binary == nil || file.Binary.Format != "ELF" || file.Binary.Machine == "" || file.SHA256 == "" {
		t.Fatalf("ELF metadata missing: %#v", file)
	}
	if _, exists := result.Contents["helper"]; exists {
		t.Fatal("ELF bytes were exposed to source analyzers")
	}
	if result.ReadBytes != 0 || result.BinaryBytes != int64(len(data)) {
		t.Fatalf("budgets misclassified: source=%d binary=%d", result.ReadBytes, result.BinaryBytes)
	}
}

func mustWrite(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func byPath(result Result) map[string]report.File {
	files := make(map[string]report.File)
	for _, file := range result.Files {
		files[file.Path] = file
	}
	return files
}

func hasLimitation(result Result, code string) bool {
	for _, limitation := range result.Limitations {
		if limitation.Code == code {
			return true
		}
	}
	return false
}
