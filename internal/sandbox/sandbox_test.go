package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/policy"
)

func TestArgumentsKeepNetworkAndHostFilesystemUnshared(t *testing.T) {
	args := Arguments("/proc/self/fd/3", "/proc/self/fd/4", "org.example.plugin")
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"--unshare-all", "--unshare-user", "--disable-userns",
		"--assert-userns-disabled", "--cap-drop ALL", "--clearenv",
		"--ro-bind /proc/self/fd/3 /app/plug-prejudice",
		"--ro-bind /proc/self/fd/4 /target",
		"--display-name org.example.plugin",
		"--sandboxed --resource-limited",
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

func TestValidDisplayName(t *testing.T) {
	for _, value := range []string{"", ".hidden", "../escape", "two..dots", "name/child", strings.Repeat("a", 256)} {
		if validDisplayName(value) {
			t.Errorf("validDisplayName(%q) = true", value)
		}
	}
	for _, value := range []string{"org.example.plugin", "Plugin-1", "plugin_name"} {
		if !validDisplayName(value) {
			t.Errorf("validDisplayName(%q) = false", value)
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

func TestOpenPinnedRejectsIntermediateSymlink(t *testing.T) {
	realDirectory := t.TempDir()
	file := filepath.Join(realDirectory, "scanner")
	if err := os.WriteFile(file, []byte("data"), 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDirectory := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := openPinned(filepath.Join(linkedDirectory, "scanner"), false); err == nil {
		t.Fatal("openPinned accepted an intermediate symlink")
	}
}

func TestProductionRunnerRejectsUserOwnedScanner(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("user-ownership rejection requires an unprivileged test user")
	}
	probe := filepath.Join(t.TempDir(), "scanner")
	data, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(probe, data, 0o700); err != nil {
		t.Fatal(err)
	}
	target := probeTarget(t)
	runner := Runner{Bubblewrap: "/usr/bin/bwrap", Timeout: time.Second}
	if _, err := runner.Run(context.Background(), probe, target, "untrusted"); err == nil || !strings.Contains(err.Error(), "expected 0") {
		t.Fatalf("untrusted scanner result = %v", err)
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

func TestRequireStaticELFRejectsDynamicELF(t *testing.T) {
	file, err := os.Open("/usr/bin/true")
	if err != nil {
		t.Skipf("dynamic system executable unavailable: %v", err)
	}
	defer file.Close()
	if err := requireStaticELF(file); err == nil || !strings.Contains(err.Error(), "dynamically linked") {
		t.Fatalf("dynamic ELF result = %v", err)
	}
}

func TestExtraFilesMapExactScannerAndTargetIdentitiesToThreeAndFour(t *testing.T) {
	if os.Getenv("PLUG_PREJUDICE_DESCRIPTOR_IDENTITY_CHILD") == "1" {
		for descriptor, variable := range map[int]string{3: "PLUG_PREJUDICE_EXPECT_FD3", 4: "PLUG_PREJUDICE_EXPECT_FD4"} {
			file := os.NewFile(uintptr(descriptor), "inherited")
			if file == nil {
				t.Fatalf("descriptor %d is unavailable", descriptor)
			}
			got, err := descriptorIdentity(file)
			if err != nil || got != os.Getenv(variable) {
				t.Fatalf("descriptor %d identity = %q, %v; want %q", descriptor, got, err, os.Getenv(variable))
			}
		}
		return
	}
	var unrelated []*os.File
	for range 24 {
		file, err := os.Open("/dev/null")
		if err != nil {
			t.Fatal(err)
		}
		unrelated = append(unrelated, file)
		defer file.Close()
	}
	scanner, err := os.Open("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	target, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if scanner.Fd() < 20 || target.Fd() < 20 {
		t.Fatalf("test did not obtain nontrivial parent descriptors: scanner=%d target=%d", scanner.Fd(), target.Fd())
	}
	scannerIdentity, err := descriptorIdentity(scanner)
	if err != nil {
		t.Fatal(err)
	}
	targetIdentity, err := descriptorIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestExtraFilesMapExactScannerAndTargetIdentitiesToThreeAndFour$")
	cmd.ExtraFiles = []*os.File{scanner, target}
	cmd.Env = append(os.Environ(),
		"PLUG_PREJUDICE_DESCRIPTOR_IDENTITY_CHILD=1",
		"PLUG_PREJUDICE_EXPECT_FD3="+scannerIdentity,
		"PLUG_PREJUDICE_EXPECT_FD4="+targetIdentity,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("descriptor identity child: %v: %s", err, output)
	}
}

func descriptorIdentity(file *os.File) (string, error) {
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("descriptor stat identity unavailable")
	}
	return strconv.FormatUint(uint64(stat.Dev), 10) + ":" + strconv.FormatUint(stat.Ino, 10) + ":" + info.Mode().Type().String(), nil
}

func TestBubblewrapIsolation(t *testing.T) {
	bwrap, probe := trustedProbe(t)
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
	targetFile, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer targetFile.Close()
	runner := Runner{Bubblewrap: bwrap, Timeout: 5 * time.Second, AllowDevelopmentScanner: true}
	output, err := runner.Run(context.Background(), probe, targetFile, "org.example.probe")
	if err != nil {
		t.Fatalf("run sandbox probe: %v", err)
	}
	var result map[string]bool
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode probe output: %v: %q", err, output)
	}
	for _, denied := range []string{"readHostEtc", "readHostHome", "writeTarget", "network", "seeHostProc", "seeSessionSocket", "nestedUserNamespace", "cgroupMigration"} {
		if result[denied] {
			t.Errorf("sandbox unexpectedly permitted %s", denied)
		}
	}
	if !result["readTarget"] || !result["writeTmp"] || !result["environmentMinimal"] {
		t.Errorf("sandbox did not provide its intended minimum access: %#v", result)
	}
}

func TestBubblewrapBoundsDescendantHoldingOutputDescriptors(t *testing.T) {
	bwrap, probe := trustedProbe(t)
	target := probeTarget(t)
	runner := Runner{Bubblewrap: bwrap, Timeout: 150 * time.Millisecond, AllowDevelopmentScanner: true}
	started := time.Now()
	_, err := runner.Run(context.Background(), probe, target, "descendant")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("descendant timeout result = %v", err)
	}
	if elapsed := time.Since(started); elapsed > runner.Timeout+policy.ProcessWaitDelay+time.Second {
		t.Fatalf("descendant holding pipes delayed teardown for %s", elapsed)
	}
}

func TestBubblewrapBoundsSimultaneousStdoutAndStderrExhaustion(t *testing.T) {
	bwrap, probe := trustedProbe(t)
	target := probeTarget(t)
	runner := Runner{Bubblewrap: bwrap, Timeout: 5 * time.Second, AllowDevelopmentScanner: true}
	started := time.Now()
	_, err := runner.Run(context.Background(), probe, target, "both-output")
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("simultaneous output result = %v", err)
	}
	if elapsed := time.Since(started); elapsed > policy.ProcessWaitDelay+time.Second {
		t.Fatalf("simultaneous output teardown took %s", elapsed)
	}
}

func TestBubblewrapBoundsAsymmetricOutputExhaustionWithRetainedPipe(t *testing.T) {
	for _, mode := range []string{"stdout-overflow-stderr-held", "stderr-overflow-stdout-held"} {
		t.Run(mode, func(t *testing.T) {
			bwrap, probe := trustedProbe(t)
			target := probeTarget(t)
			runner := Runner{Bubblewrap: bwrap, Timeout: 5 * time.Second, AllowDevelopmentScanner: true}
			started := time.Now()
			_, err := runner.Run(context.Background(), probe, target, mode)
			if err == nil || !strings.Contains(err.Error(), "exceeded") {
				t.Fatalf("asymmetric output result = %v", err)
			}
			if elapsed := time.Since(started); elapsed > policy.ProcessWaitDelay+time.Second {
				t.Fatalf("retained opposite pipe delayed teardown for %s", elapsed)
			}
		})
	}
}

func TestBubblewrapWallClockTimeout(t *testing.T) {
	bwrap, probe := trustedProbe(t)
	target := probeTarget(t)
	runner := Runner{Bubblewrap: bwrap, Timeout: 100 * time.Millisecond, AllowDevelopmentScanner: true}
	_, err := runner.Run(context.Background(), probe, target, "timeout")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout result = %v", err)
	}
}

func TestBubblewrapRejectsOversizedOutput(t *testing.T) {
	bwrap, probe := trustedProbe(t)
	target := probeTarget(t)
	runner := Runner{Bubblewrap: bwrap, Timeout: 5 * time.Second, AllowDevelopmentScanner: true}
	_, err := runner.Run(context.Background(), probe, target, "output")
	if err == nil || !strings.Contains(err.Error(), "output exceeded") {
		t.Fatalf("oversized output result = %v", err)
	}
}

func trustedProbe(t *testing.T) (string, string) {
	t.Helper()
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
	return bwrap, probe
}

func probeTarget(t *testing.T) *os.File {
	t.Helper()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "manifest.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}
