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
