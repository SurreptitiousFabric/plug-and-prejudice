package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/policy"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestLiveBrokerListOverflowFailsInsideResourceScope(t *testing.T) {
	if output, err := exec.Command("systemctl", "--user", "is-system-running").CombinedOutput(); err != nil && strings.TrimSpace(string(output)) != "degraded" {
		t.Skipf("user systemd manager is unavailable: %v: %s", err, output)
	}
	root := t.TempDir()
	for index := 0; index <= maxInstalledPlugins; index++ {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("plugin-%04d", index)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	broker := filepath.Join(t.TempDir(), "plug-prejudice-broker")
	build := exec.Command("go", "build", "-o", broker, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build broker: %v: %s", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, broker, "--list", "--plugins-root", root)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "entry count exceeds") {
		t.Fatalf("contained list overflow = %v: %s", err, output)
	}
}

func TestPluginStorageActionRunsOnlyAfterEveryContainmentCheck(t *testing.T) {
	var events []string
	checks := containmentChecks{
		verify: func(string) error {
			events = append(events, "cgroup")
			return nil
		},
		verifyRuntime: func(context.Context, string) error {
			events = append(events, "runtime")
			return nil
		},
		applyLimits: func() error {
			events = append(events, "rlimits")
			return nil
		},
	}
	result := afterVerifiedContainment("plug-prejudice-0123456789abcdef01234567.scope", checks, func() int {
		events = append(events, "plugin-storage")
		return 0
	})
	want := []string{"cgroup", "runtime", "rlimits", "plugin-storage"}
	if result != 0 || !reflect.DeepEqual(events, want) {
		t.Fatalf("contained action = %d, %q; want 0, %q", result, events, want)
	}
}

func TestContainmentFailurePreventsPluginStorageAction(t *testing.T) {
	for _, failed := range []string{"cgroup", "runtime", "rlimits"} {
		t.Run(failed, func(t *testing.T) {
			var actionCalled bool
			failure := func(name string) error {
				if name == failed {
					return fmt.Errorf("%s unavailable", name)
				}
				return nil
			}
			checks := containmentChecks{
				verify:        func(string) error { return failure("cgroup") },
				verifyRuntime: func(context.Context, string) error { return failure("runtime") },
				applyLimits:   func() error { return failure("rlimits") },
			}
			if result := afterVerifiedContainment("plug-prejudice-0123456789abcdef01234567.scope", checks, func() int {
				actionCalled = true
				return 0
			}); result == 0 || actionCalled {
				t.Fatalf("%s failure result=%d actionCalled=%v", failed, result, actionCalled)
			}
		})
	}
}

func TestInstalledPluginIDsListsOnlyRealValidDirectories(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"org.example.alpha", "zeta"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
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

func TestInstalledPluginIDsFailsClosedOnUnacceptableOrExcessEntries(t *testing.T) {
	t.Run("unacceptable", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "plain-file"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := installedPluginIDs(root); err == nil {
			t.Fatal("unacceptable plugin-root entry was ignored")
		}
	})
	t.Run("overflow", func(t *testing.T) {
		root := t.TempDir()
		for index := 0; index <= maxInstalledPlugins; index++ {
			if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("plugin-%04d", index)), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := installedPluginIDs(root); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("overflow result = %v", err)
		}
	})
}

func TestExpectedResourceLimitsRequiresExactPolicy(t *testing.T) {
	limits := &report.ResourceLimits{
		MemoryMaxBytes: policy.MemoryMaxBytes, MemorySwapBytes: policy.MemorySwapBytes,
		TasksMax: policy.TasksMax, CPUQuotaPercent: policy.CPUQuotaPercent,
		WallTimeSeconds: int(policy.WallTime.Seconds()),
	}
	if !expectedResourceLimits(limits) {
		t.Fatal("exact resource policy was rejected")
	}
	limits.TasksMax++
	if expectedResourceLimits(limits) {
		t.Fatal("mismatched resource policy was accepted")
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

func TestOpenInstalledTargetPinsDirectoryAcrossPathReplacement(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "plugin")
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, "identity"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := openInstalledTarget(root, "plugin")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := os.Rename(original, filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/identity", target.Fd()))
	if err != nil || string(data) != "original" {
		t.Fatalf("pinned target read = %q, %v", data, err)
	}
}

func TestOpenInstalledTargetRejectsSymlinkTraversal(t *testing.T) {
	realRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(realRoot, "plugin"), 0o700); err != nil {
		t.Fatal(err)
	}
	linkedRoot := filepath.Join(t.TempDir(), "plugins")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := openInstalledTarget(linkedRoot, "plugin"); err == nil {
		t.Fatal("intermediate root symlink was accepted")
	}
	if err := os.Symlink(filepath.Join(realRoot, "plugin"), filepath.Join(realRoot, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := openInstalledTarget(realRoot, "linked"); err == nil {
		t.Fatal("target symlink was accepted")
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
