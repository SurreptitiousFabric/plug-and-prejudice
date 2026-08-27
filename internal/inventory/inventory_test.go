package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

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
