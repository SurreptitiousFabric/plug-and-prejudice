package resource

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/policy"
)

func TestArgumentsContainEveryApprovedLimit(t *testing.T) {
	unit := "plug-prejudice-0123456789abcdef01234567.scope"
	joined := strings.Join(Arguments(unit, "/proc/123/exe", []string{"--plugin", "example"}), " ")
	for _, required := range []string{
		"--user --scope", "--unit " + unit, "--quiet --collect",
		"--property=MemoryMax=268435456", "--property=MemorySwapMax=0",
		"--property=TasksMax=64", "--property=CPUQuota=100%",
		"--property=RuntimeMaxSec=35s", "-- /proc/123/exe --plugin example",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("resource arguments omit %q: %s", required, joined)
		}
	}
}

func TestVerifyAcceptsExpectedCgroupLimits(t *testing.T) {
	unit := "plug-prejudice-0123456789abcdef01234567.scope"
	root := t.TempDir()
	path := filepath.Join("user.slice", unit)
	directory := filepath.Join(root, path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, name), []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("memory.max", "268435456")
	write("memory.swap.max", "0")
	write("pids.max", "64")
	write("cpu.max", "100000 100000")
	proc := filepath.Join(root, "proc-cgroup")
	if err := os.WriteFile(proc, []byte("0::/"+path+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := Manager{CgroupRoot: root, ProcCgroup: proc}
	if err := manager.Verify(unit); err != nil {
		t.Fatalf("Verify() = %v", err)
	}
}

func TestVerifyRejectsMissingWrongOrUnlimitedControls(t *testing.T) {
	unit := "plug-prejudice-0123456789abcdef01234567.scope"
	tests := []struct {
		name   string
		values map[string]string
	}{
		{name: "memory unlimited", values: map[string]string{"memory.max": "max", "memory.swap.max": "0", "pids.max": "64", "cpu.max": "100000 100000"}},
		{name: "too many tasks", values: map[string]string{"memory.max": "268435456", "memory.swap.max": "0", "pids.max": "65", "cpu.max": "100000 100000"}},
		{name: "cpu unlimited", values: map[string]string{"memory.max": "268435456", "memory.swap.max": "0", "pids.max": "64", "cpu.max": "max 100000"}},
		{name: "cpu overflow input", values: map[string]string{"memory.max": "268435456", "memory.swap.max": "0", "pids.max": "64", "cpu.max": "9223372036854775807 1"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, unit)
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, value := range test.values {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(value), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			proc := filepath.Join(root, "proc-cgroup")
			if err := os.WriteFile(proc, []byte("0::/"+unit+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := (Manager{CgroupRoot: root, ProcCgroup: proc}).Verify(unit); err == nil {
				t.Fatal("unsafe cgroup limits were accepted")
			}
		})
	}
}

func TestPolicyValuesRemainIntentional(t *testing.T) {
	if policy.MemoryMaxBytes != 256<<20 || policy.TasksMax != 64 || policy.CPUQuotaPercent != 100 || policy.WallTime.Seconds() != 30 {
		t.Fatal("resource policy changed without updating its contract tests")
	}
}

func TestLiveSystemdScopeEnforcesVerifiableControls(t *testing.T) {
	if os.Getenv("PLUG_PREJUDICE_RESOURCE_HELPER") == "1" {
		manager, err := DefaultManager()
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Verify(os.Getenv("PLUG_PREJUDICE_RESOURCE_UNIT")); err != nil {
			t.Fatal(err)
		}
		if err := manager.VerifyRuntime(context.Background(), os.Getenv("PLUG_PREJUDICE_RESOURCE_UNIT")); err != nil {
			t.Fatal(err)
		}
		return
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("systemd-run is unavailable")
	}
	if output, err := exec.Command("systemctl", "--user", "is-system-running").CombinedOutput(); err != nil && strings.TrimSpace(string(output)) != "degraded" {
		t.Skipf("user systemd manager is unavailable: %v: %s", err, output)
	}
	manager, err := DefaultManager()
	if err != nil {
		t.Fatal(err)
	}
	unit, err := NewUnitName()
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PLUG_PREJUDICE_RESOURCE_HELPER", "1")
	t.Setenv("PLUG_PREJUDICE_RESOURCE_UNIT", unit)
	if err := manager.Run(context.Background(), unit, executable, []string{"-test.run=^TestLiveSystemdScopeEnforcesVerifiableControls$"}); err != nil {
		t.Fatalf("live resource scope: %v", err)
	}
}

func TestVerifyRuntimeMaxRejectsMissingUnlimitedAndWeakValues(t *testing.T) {
	for _, value := range []string{"35s", "30s", "1us"} {
		if err := verifyRuntimeMax(value); err != nil {
			t.Errorf("%q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"", "infinity", "0", "36s", "not-duration"} {
		if err := verifyRuntimeMax(value); err == nil {
			t.Errorf("%q accepted", value)
		}
	}
}

func TestLiveSystemdScopeEnforcesMemoryMax(t *testing.T) {
	if os.Getenv("PLUG_PREJUDICE_RESOURCE_HELPER") == "memory" {
		allocation := make([]byte, 320<<20)
		for index := 0; index < len(allocation); index += 4096 {
			allocation[index] = 1
		}
		runtime.KeepAlive(allocation)
		os.Exit(99)
	}
	manager, unit, executable := liveScopeTest(t)
	t.Setenv("PLUG_PREJUDICE_RESOURCE_HELPER", "memory")
	if err := manager.Run(context.Background(), unit, executable, []string{"-test.run=^TestLiveSystemdScopeEnforcesMemoryMax$"}); err == nil {
		t.Fatal("memory exhaustion survived the systemd scope")
	}
}

func TestLiveSystemdScopeEnforcesTasksMax(t *testing.T) {
	if os.Getenv("PLUG_PREJUDICE_RESOURCE_HELPER") == "tasks" {
		var children []*exec.Cmd
		denied := false
		for range policy.TasksMax * 2 {
			child := exec.Command("/usr/bin/sleep", "5")
			if err := child.Start(); err != nil {
				denied = true
				break
			}
			children = append(children, child)
		}
		for _, child := range children {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
		if !denied {
			os.Exit(99)
		}
		return
	}
	manager, unit, executable := liveScopeTest(t)
	t.Setenv("PLUG_PREJUDICE_RESOURCE_HELPER", "tasks")
	if err := manager.Run(context.Background(), unit, executable, []string{"-test.run=^TestLiveSystemdScopeEnforcesTasksMax$"}); err != nil {
		t.Fatalf("task-limit helper failed: %v", err)
	}
}

func liveScopeTest(t *testing.T) (Manager, string, string) {
	t.Helper()
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("systemd-run is unavailable")
	}
	if output, err := exec.Command("systemctl", "--user", "is-system-running").CombinedOutput(); err != nil && strings.TrimSpace(string(output)) != "degraded" {
		t.Skipf("user systemd manager is unavailable: %v: %s", err, output)
	}
	manager, err := DefaultManager()
	if err != nil {
		t.Fatal(err)
	}
	unit, err := NewUnitName()
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return manager, unit, executable
}
