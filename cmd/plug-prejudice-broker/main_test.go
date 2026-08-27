package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestInstalledPluginIDsListsOnlyRealValidDirectories(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"org.example.alpha", "zeta"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, ".hidden"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "plain-file"), []byte("not a plugin"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "zeta"), filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}

	got, err := installedPluginIDs(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"org.example.alpha", "zeta"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("installedPluginIDs() = %q, want %q", got, want)
	}
}

func TestInstalledPluginIDsRejectsSymlinkRoot(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(t.TempDir(), "plugins")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := installedPluginIDs(link); err == nil {
		t.Fatal("symlink plugin root was accepted")
	}
}

func TestValidPluginID(t *testing.T) {
	for _, value := range []string{"", ".hidden", "../escape", "a/child", "two..dots", "space name"} {
		if validPluginID(value) {
			t.Errorf("validPluginID(%q) = true", value)
		}
	}
	for _, value := range []string{"org.example.plugin", "plugin-name", "plugin_name", "Plugin1"} {
		if !validPluginID(value) {
			t.Errorf("validPluginID(%q) = false", value)
		}
	}
}
