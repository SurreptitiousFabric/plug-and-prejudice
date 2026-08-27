package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestArgumentsKeepNetworkAndHostFilesystemUnshared(t *testing.T) {
	args := Arguments("/proc/self/fd/3", "/proc/self/fd/4")
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"--unshare-all", "--unshare-user", "--disable-userns",
		"--assert-userns-disabled", "--cap-drop ALL", "--clearenv",
		"--ro-bind /proc/self/fd/3 /app/plug-prejudice",
		"--ro-bind /proc/self/fd/4 /target",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("sandbox arguments omit %q: %s", required, joined)
		}
	}
	for _, forbidden := range []string{"--share-net", "--bind /home", "--ro-bind /home", "--proc /proc"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("sandbox arguments contain forbidden %q: %s", forbidden, joined)
		}
	}
}

func TestOpenPinnedRejectsEndpointSymlink(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "target-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openPinned(link, true); err == nil {
		t.Fatal("openPinned accepted a symlink endpoint")
	}
}

func TestRequireStaticELFRejectsNonELF(t *testing.T) {
	name := filepath.Join(t.TempDir(), "scanner")
	if err := os.WriteFile(name, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := requireStaticELF(file); err == nil {
		t.Fatal("non-ELF scanner was accepted")
	}
}

func TestBubblewrapIsolation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Bubblewrap integration requires Linux")
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("Bubblewrap is unavailable")
	}
	probe := filepath.Join(t.TempDir(), "probe")
	build := exec.Command("go", "build", "-o", probe, "./testdata/probe")
	build.Dir = "."
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build trusted sandbox probe: %v: %s", err, output)
	}
	probeFile, err := os.Open(probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireStaticELF(probeFile); err != nil {
		_ = probeFile.Close()
		t.Fatalf("static probe was rejected: %v", err)
	}
	if err := probeFile.Close(); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "manifest.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := Runner{Bubblewrap: bwrap, Timeout: 5 * time.Second}
	output, err := runner.Run(context.Background(), probe, target)
	if err != nil {
		t.Fatalf("run sandbox probe: %v", err)
	}
	var result map[string]bool
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode probe output: %v: %q", err, output)
	}
	for _, denied := range []string{"readHostEtc", "readHostHome", "writeTarget", "network", "seeHostProc"} {
		if result[denied] {
			t.Errorf("sandbox unexpectedly permitted %s", denied)
		}
	}
	if !result["readTarget"] || !result["writeTmp"] || !result["environmentMinimal"] {
		t.Errorf("sandbox did not provide its intended minimum access: %#v", result)
	}
}
