package trustedexec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRequireAcceptsRootOwnedSystemExecutable(t *testing.T) {
	if _, err := os.Stat("/usr/bin/true"); err != nil {
		t.Skip("standard system executable is unavailable")
	}
	if _, err := Require("/usr/bin/true"); err != nil {
		t.Fatalf("Require() = %v", err)
	}
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
	if _, err := Require("usr/bin/true"); err == nil {
		t.Fatal("relative executable was accepted")
	}
	root := t.TempDir()
	link := filepath.Join(root, "linked")
	if err := os.Symlink("/usr/bin/true", link); err != nil {
		t.Fatal(err)
	}
	if _, err := Require(link); err == nil {
		t.Fatal("symlink executable was accepted")
	}
	file := filepath.Join(root, "executable")
	if err := os.WriteFile(file, []byte("test"), 0o700); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		if _, err := Require(file); err == nil {
			t.Fatal("user-owned executable was accepted")
		}
	}
}
