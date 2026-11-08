package inventory

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
	"golang.org/x/sys/unix"
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

func TestScanRejectsSymlinkTargetEndpoint(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "target-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(link, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink target result = %v", err)
	}
}

func TestStableReadRejectsChangedSizeAndMetadata(t *testing.T) {
	name := filepath.Join(t.TempDir(), "source")
	mustWrite(t, name, "original")
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !stableRead(file, before, before.Size()) {
		t.Fatal("unchanged file was rejected")
	}
	if stableRead(file, before, before.Size()-1) {
		t.Fatal("short read was accepted")
	}
	alias := filepath.Join(filepath.Dir(name), "alias")
	if err := os.Link(name, alias); err == nil {
		if stableRead(file, before, before.Size()) {
			t.Fatal("file that gained a hard link was accepted")
		}
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Truncate(name, 1); err != nil {
		t.Fatal(err)
	}
	if stableRead(file, before, before.Size()) {
		t.Fatal("changed file was accepted")
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
	if len(result.Files) != 0 {
		t.Fatalf("overflowing directory was partially inventoried: %#v", result.Files)
	}
	if !hasLimitation(result, "max-files") {
		t.Fatal("missing max-files limitation")
	}
}

func TestScanSkipsOnlyNestedDirectoryThatExceedsRemainingFileLimit(t *testing.T) {
	target := t.TempDir()
	for _, name := range []string{"a/one", "a/two", "a/three", "z"} {
		mustWrite(t, filepath.Join(target, name), name)
	}
	limits := DefaultLimits()
	limits.MaxFiles = 3
	result, err := Scan(target, limits)
	if err != nil {
		t.Fatal(err)
	}
	files := byPath(result)
	if len(files) != 2 || files["a"].Kind != "directory" || !files["z"].Inspected {
		t.Fatalf("bounded sibling inventory = %#v", result.Files)
	}
	for _, nested := range []string{"a/one", "a/two", "a/three"} {
		if _, exists := files[nested]; exists {
			t.Fatalf("overflowing nested directory entry %q was inventoried", nested)
		}
	}
	if !hasLimitationAt(result, "max-files", "a") {
		t.Fatalf("nested max-files limitation missing: %#v", result.Limitations)
	}
}

func TestRootDigestIsDeterministicAndBindsInspectedBytes(t *testing.T) {
	target := t.TempDir()
	mustWrite(t, filepath.Join(target, "b"), "second")
	mustWrite(t, filepath.Join(target, "a"), "first")
	first, err := Scan(target, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Scan(target, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if first.RootDigest == "" || first.RootDigest != second.RootDigest {
		t.Fatalf("root digest is not deterministic: %q != %q", first.RootDigest, second.RootDigest)
	}
	mustWrite(t, filepath.Join(target, "a"), "other")
	changed, err := Scan(target, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if changed.RootDigest == first.RootDigest {
		t.Fatal("root digest did not bind changed source bytes")
	}
}

func TestDefaultFileLimitMatchesReportContract(t *testing.T) {
	if got := DefaultLimits().MaxFiles; got != report.MaxInventoryEntries {
		t.Fatalf("inventory file limit %d does not match report limit %d", got, report.MaxInventoryEntries)
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

func TestScanStopsAtTotalSourceByteLimit(t *testing.T) {
	target := t.TempDir()
	mustWrite(t, filepath.Join(target, "a"), "12345678")
	mustWrite(t, filepath.Join(target, "b"), "abcdefgh")
	limits := DefaultLimits()
	limits.MaxReadBytes = 8
	result, err := Scan(target, limits)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReadBytes != 8 || !byPath(result)["a"].Inspected || byPath(result)["b"].Inspected {
		t.Fatalf("source budget was not enforced deterministically: %#v", result)
	}
	if !hasLimitation(result, "max-total-bytes") {
		t.Fatal("missing max-total-bytes limitation")
	}
}

func TestScanStopsAtDepthLimit(t *testing.T) {
	target := t.TempDir()
	mustWrite(t, filepath.Join(target, "one", "two", "hidden"), "data")
	limits := DefaultLimits()
	limits.MaxDepth = 1
	result, err := Scan(target, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := byPath(result)["one/two/hidden"]; exists {
		t.Fatal("file below depth limit was inventoried")
	}
	if !hasLimitation(result, "max-depth") {
		t.Fatalf("missing max-depth limitation: %#v", result)
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

func TestScanDoesNotReadMultiLinkFileThatMayAliasOutsideTarget(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "plugin")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "unrelated-secret")
	mustWrite(t, outside, "must not be inspected")
	inside := filepath.Join(target, "innocent-name")
	if err := os.Link(outside, inside); err != nil {
		t.Skipf("hard links are unavailable on this filesystem: %v", err)
	}
	result, err := Scan(target, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	file := byPath(result)["innocent-name"]
	if file.Inspected || file.SHA256 != "" || file.SkipReason != "multiple-hard-links" {
		t.Fatalf("multi-link file was not safely skipped: %#v", file)
	}
	if _, exists := result.Contents["innocent-name"]; exists {
		t.Fatal("multi-link bytes reached source analysis")
	}
	if result.ReadBytes != 0 || !hasLimitation(result, "multiple-hard-links") {
		t.Fatalf("multi-link omission was not explicit: %#v", result)
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
		t.Fatalf("Git database file was not explicitly skipped: %#v result=%#v", file, result)
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

func TestPrintableStringsAndURLsAreBoundedStaticMetadata(t *testing.T) {
	stringsFound, truncated := printableStrings([]byte("\x00ordinary\x00https://api.example.test/v1\x00"))
	if truncated || len(stringsFound) != 2 {
		t.Fatalf("strings = %#v, truncated=%t", stringsFound, truncated)
	}
	urls, truncated := embeddedURLs(stringsFound)
	if truncated || len(urls) != 1 || urls[0] != "https://api.example.test/v1" {
		t.Fatalf("urls = %#v, truncated=%t", urls, truncated)
	}
}

func TestParseFileCapabilitiesUnionsPermittedAndInheritable(t *testing.T) {
	data := []byte{1, 0, 0, 2, 0x80, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	values, effective, ok := parseFileCapabilities(data)
	if !ok || !effective || len(values) != 2 || values[0] != "CAP_SETUID" || values[1] != "CAP_NET_ADMIN" {
		t.Fatalf("capabilities = %#v, effective=%t, ok=%t", values, effective, ok)
	}
}

func TestParseFileCapabilitiesRejectsMalformedMetadata(t *testing.T) {
	if _, _, ok := parseFileCapabilities([]byte{1, 2, 3}); ok {
		t.Fatal("malformed capability metadata accepted")
	}
}

func TestScanKeepsMalformedELFOutOfSourceAnalysis(t *testing.T) {
	target := t.TempDir()
	data := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0}, 60)...)
	if err := os.WriteFile(filepath.Join(target, "hostile-elf"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Scan(target, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	file := byPath(result)["hostile-elf"]
	if !file.Inspected || file.SHA256 == "" || file.ContentType != "application/x-elf" || file.Binary != nil {
		t.Fatalf("malformed ELF inventory is incomplete: %#v", file)
	}
	if _, exists := result.Contents["hostile-elf"]; exists {
		t.Fatal("malformed ELF bytes were exposed to source analyzers")
	}
	if result.ReadBytes != 0 || result.BinaryBytes != int64(len(data)) {
		t.Fatalf("malformed ELF consumed the wrong budget: source=%d binary=%d", result.ReadBytes, result.BinaryBytes)
	}
	if !hasLimitation(result, "elf-parse-error") {
		t.Fatal("missing elf-parse-error limitation")
	}
}

func TestScanEnforcesELFFileLimitBeforeReadingBinary(t *testing.T) {
	target := t.TempDir()
	data := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0}, 60)...)
	if err := os.WriteFile(filepath.Join(target, "large-elf"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxBinaryFileBytes = int64(len(data) - 1)
	result, err := Scan(target, limits)
	if err != nil {
		t.Fatal(err)
	}
	file := byPath(result)["large-elf"]
	if file.Inspected || file.SHA256 != "" || result.BinaryBytes != 0 {
		t.Fatalf("oversize ELF was read: %#v, binary bytes %d", file, result.BinaryBytes)
	}
	if !hasLimitation(result, "max-binary-file-bytes") {
		t.Fatal("missing max-binary-file-bytes limitation")
	}
}

func TestInventoryEncodedStringBudgetExactAndFirstOver(t *testing.T) {
	file := report.File{Path: "file", Kind: "regular", Mode: "-rw-r--r--"}
	values := []string{file.Path, file.Kind, file.Mode, file.SHA256, file.ContentType, file.LinkTarget, file.SkipReason}
	charge := 0
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		charge += len(encoded)
	}
	exact := walker{retainedEncodedStringBytes: maxInventoryEncodedStringBytes - charge, result: Result{Contents: map[string][]byte{}}}
	if !exact.appendFile(file) || exact.retainedEncodedStringBytes != maxInventoryEncodedStringBytes {
		t.Fatalf("exact inventory budget = %d, files %d", exact.retainedEncodedStringBytes, len(exact.result.Files))
	}
	over := walker{retainedEncodedStringBytes: maxInventoryEncodedStringBytes - charge + 1, result: Result{Contents: map[string][]byte{}}}
	if over.appendFile(file) || len(over.result.Files) != 0 || !over.inventoryBudgetExhausted || !hasLimitation(over.result, "result-production-limit") {
		t.Fatalf("first over inventory budget = %#v", over)
	}
}

func TestInventoryBudgetRollbackKeepsByteTotalsConsistent(t *testing.T) {
	file := report.File{Path: "file", Kind: "regular", Mode: "-rw-r--r--", Size: 4, Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain"}
	w := walker{retainedEncodedStringBytes: maxInventoryEncodedStringBytes, result: Result{Contents: map[string][]byte{"file": []byte("data")}, ReadBytes: 4}}
	if w.appendFile(file) || w.result.ReadBytes != 0 || w.result.Contents["file"] != nil {
		t.Fatalf("rollback result = %#v", w.result)
	}
}

func TestArchiveStringsConsumeInventoryProductionBudget(t *testing.T) {
	file := report.File{Path: "payload.zip", Kind: "regular", Mode: "-rw-------", Archive: &report.Archive{Format: "zip", Entries: []report.ArchiveEntry{{Path: "member-name", Kind: "file", Mode: "-rw-------", LinkTarget: "target"}}}}
	values := []string{file.Path, file.Kind, file.Mode, file.SHA256, file.ContentType, file.LinkTarget, file.SkipReason, "zip", "member-name", "file", "-rw-------", "target"}
	charge := 0
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		charge += len(encoded)
	}
	exact := walker{retainedEncodedStringBytes: maxInventoryEncodedStringBytes - charge, result: Result{Contents: map[string][]byte{}}}
	if !exact.appendFile(file) || exact.retainedEncodedStringBytes != maxInventoryEncodedStringBytes {
		t.Fatalf("archive exact inventory budget = %#v", exact)
	}
	over := walker{retainedEncodedStringBytes: maxInventoryEncodedStringBytes - charge + 1, result: Result{Contents: map[string][]byte{}}}
	if over.appendFile(file) || !over.inventoryBudgetExhausted {
		t.Fatalf("archive strings bypassed inventory budget: %#v", over)
	}
}

func TestScanDoesNotReadSameFilesystemBindMount(t *testing.T) {
	target := t.TempDir()
	outside := t.TempDir()
	mountpoint := filepath.Join(target, "nested")
	if err := os.Mkdir(mountpoint, 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(outside, "secret"), "must not be read")
	if err := unix.Mount(outside, mountpoint, "", unix.MS_BIND, ""); err != nil {
		if err == unix.EPERM || err == unix.EACCES {
			t.Skip("kernel forbids an unprivileged bind-mount fixture")
		}
		t.Fatalf("create controlled bind mount: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(mountpoint, unix.MNT_DETACH) })
	result, err := Scan(target, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	nested := byPath(result)["nested"]
	if nested.SkipReason != "nested-mount" || !hasLimitationAt(result, "nested-mount", "nested") {
		t.Fatalf("nested mount boundary = %#v, limitations %#v", nested, result.Limitations)
	}
	if _, exists := byPath(result)["nested/secret"]; exists || result.Contents["nested/secret"] != nil {
		t.Fatal("content below nested mount was read")
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

func TestScanInventoriesZIPAndTARMetadataWithoutExtraction(t *testing.T) {
	target := t.TempDir()
	zipData := archiveZIP(t, []archiveTestEntry{{name: "bin/helper.sh", body: "#!/bin/sh\nwhoami\n"}, {name: "../escape", body: "payload"}, {name: "link", body: "target", mode: os.ModeSymlink | 0o777}})
	tarData := archiveTAR(t, []archiveTestEntry{{name: "config/example.conf", body: "value"}, {name: "linked", link: "../../outside", mode: os.ModeSymlink | 0o777}})
	if err := os.WriteFile(filepath.Join(target, "payload.zip"), zipData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "payload.tar"), tarData, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Scan(target, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	files := byPath(result)
	zipFile, tarFile := files["payload.zip"], files["payload.tar"]
	if zipFile.Archive == nil || zipFile.Archive.Format != "zip" || !zipFile.Archive.InventoryComplete || len(zipFile.Archive.Entries) != 3 || !zipFile.Archive.Entries[1].UnsafePath {
		t.Fatalf("ZIP metadata = %#v", zipFile)
	}
	if tarFile.Archive == nil || tarFile.Archive.Format != "tar" || !tarFile.Archive.InventoryComplete || len(tarFile.Archive.Entries) != 2 || tarFile.Archive.Entries[1].Kind != "symlink" || tarFile.Archive.Entries[1].LinkTarget != "../../outside" {
		t.Fatalf("TAR metadata = %#v", tarFile)
	}
	if _, exists := files["bin/helper.sh"]; exists {
		t.Fatal("archive member escaped into filesystem inventory")
	}
	if !bytes.Equal(result.Contents["payload.zip"], zipData) || !bytes.Equal(result.Contents["payload.tar"], tarData) {
		t.Fatal("archive bytes were extracted or replaced")
	}
}

func TestCompressedArchiveIsIdentifiedWithoutDecompression(t *testing.T) {
	target := t.TempDir()
	data := []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00}
	if err := os.WriteFile(filepath.Join(target, "payload.gz"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Scan(target, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	file := byPath(result)["payload.gz"]
	if file.Archive == nil || file.Archive.Format != "gzip" || file.Archive.InventoryComplete || len(file.Archive.Entries) != 0 || !hasLimitation(result, "compressed-archive-inventory-unavailable") {
		t.Fatalf("compressed archive boundary = %#v, limitations=%#v", file, result.Limitations)
	}
}

func TestArchiveEntryAndMetadataLimitsAreExplicit(t *testing.T) {
	entries := make([]archiveTestEntry, report.MaxArchiveEntries+1)
	for index := range entries {
		entries[index] = archiveTestEntry{name: fmt.Sprintf("entry-%04d", index)}
	}
	data := archiveZIP(t, entries)
	w := walker{result: Result{Contents: map[string][]byte{}}}
	archive := &report.Archive{Format: "zip", Entries: []report.ArchiveEntry{}}
	w.recordZIP(data, "many.zip", archive)
	if archive.InventoryComplete || len(archive.Entries) != report.MaxArchiveEntries || !hasLimitation(w.result, "archive-entry-limit") {
		t.Fatalf("archive entry cap = entries %d complete=%v limitations=%#v", len(archive.Entries), archive.InventoryComplete, w.result.Limitations)
	}
	longName := strings.Repeat("x", report.MaxHostileStringBytes)
	archive = &report.Archive{Format: "zip", Entries: []report.ArchiveEntry{}}
	w = walker{result: Result{Contents: map[string][]byte{}}}
	w.recordZIP(archiveZIP(t, []archiveTestEntry{{name: longName}}), "long.zip", archive)
	if archive.InventoryComplete || len(archive.Entries) != 0 || !hasLimitation(w.result, "archive-metadata-limit") {
		t.Fatalf("oversized member metadata was retained: %#v, %#v", archive, w.result.Limitations)
	}
}

type archiveTestEntry struct {
	name string
	body string
	link string
	mode os.FileMode
}

func archiveZIP(t *testing.T, entries []archiveTestEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		if entry.mode != 0 {
			header.SetMode(entry.mode)
		}
		member, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func archiveTAR(t *testing.T, entries []archiveTestEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Mode: 0o600, Size: int64(len(entry.body)), Typeflag: tar.TypeReg}
		if entry.mode&os.ModeSymlink != 0 {
			header.Typeflag = tar.TypeSymlink
			header.Linkname = entry.link
			header.Size = 0
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := writer.Write([]byte(entry.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
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

func hasLimitationAt(result Result, code, path string) bool {
	for _, limitation := range result.Limitations {
		if limitation.Code == code && limitation.Path == path {
			return true
		}
	}
	return false
}
