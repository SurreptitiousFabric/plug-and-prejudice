package trustedexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRequireAcceptsRootOwnedSystemExecutable(t *testing.T) {
	if _, err := os.Stat("/usr/bin/true"); err != nil {
		t.Skip("standard system executable is unavailable")
	}
	executable, err := Open("/usr/bin/true")
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	defer executable.Close()
}

func TestValidateModeRequiresExecutableNonWritableRegularFile(t *testing.T) {
	if err := validateMode(0o755); err != nil {
		t.Fatalf("safe executable mode was rejected: %v", err)
	}
	for _, mode := range []os.FileMode{0o644, 0o775, 0o757, os.ModeDir | 0o755} {
		if err := validateMode(mode); err == nil {
			t.Errorf("unsafe mode %v was accepted", mode)
		}
	}
}

func TestRequireRejectsRelativeSymlinkAndUserFile(t *testing.T) {
	if _, err := Open("usr/bin/true"); err == nil {
		t.Fatal("relative executable was accepted")
	}
	root := t.TempDir()
	link := filepath.Join(root, "linked")
	if err := os.Symlink("/usr/bin/true", link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("symlink executable was accepted")
	}
	file := filepath.Join(root, "executable")
	if err := os.WriteFile(file, []byte("test"), 0o700); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		if _, err := Open(file); err == nil {
			t.Fatal("user-owned executable was accepted")
		}
	}
}

func TestOpenRejectsIntermediateSymlinkAndNonELF(t *testing.T) {
	directory := t.TempDir()
	realDirectory := filepath.Join(directory, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(realDirectory, "tool")
	if err := os.WriteFile(tool, []byte("not an ELF"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := openOwned(tool, uint32(os.Getuid())); err == nil {
		t.Fatal("non-ELF executable was accepted")
	}
	linkedDirectory := filepath.Join(directory, "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := openOwned(filepath.Join(linkedDirectory, "tool"), uint32(os.Getuid())); err == nil {
		t.Fatal("intermediate directory symlink was accepted")
	}
}

func TestPinnedDescriptorSurvivesPathReplacement(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "tool")
	copyTool := func(source, destination string) {
		t.Helper()
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, data, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	copyTool("/usr/bin/true", path)
	executable, err := openOwned(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	replacement := filepath.Join(directory, "replacement")
	copyTool("/usr/bin/false", replacement)
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	procPath, args, err := executable.CommandPath()
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(procPath, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("execute pinned tool: %v: %s", err, output)
	}
	if len(output) != 0 {
		t.Fatalf("pinned true produced unexpected output %q", output)
	}
}

func TestPinnedDescriptorExecutionSurvivesExtraFileRemapping(t *testing.T) {
	executable, err := Open("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	extra, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	procPath, args, err := executable.CommandPath()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(procPath, args...)
	cmd.ExtraFiles = []*os.File{extra, extra}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("execute pinned tool with inherited descriptors: %v: %s", err, output)
	}
}

func TestOpenRejectsWritableExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("tool"), 0o722); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o722); err != nil {
		t.Fatal(err)
	}
	if _, err := openOwned(path, uint32(os.Getuid())); err == nil {
		t.Fatal("group- or world-writable executable was accepted")
	}
}
