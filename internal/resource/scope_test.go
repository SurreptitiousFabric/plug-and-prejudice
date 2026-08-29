package resource

import (
	"context"
	"errors"
	"flag"
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

var resourceHelper = flag.String("resource-helper", "", "internal live resource test mode")
var resourceUnit = flag.String("resource-unit", "", "internal live resource test unit")
var descendantPID = flag.String("descendant-pid", "", "internal live resource test pid file")

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

func TestVerifyRuntimeMaxAcceptsExactAndRejectsMissingUnlimitedOrWeak(t *testing.T) {
	for _, value := range []string{"35s", "35000000us", "34.5s"} {
		if err := verifyRuntimeMax(value); err != nil {
			t.Errorf("verifyRuntimeMax(%q) = %v", value, err)
		}
	}
	for _, value := range []string{"", "infinity", "0", "35.000001s", "1min"} {
		if err := verifyRuntimeMax(value); err == nil {
			t.Errorf("verifyRuntimeMax(%q) accepted unsafe value", value)
		}
	}
}

func TestUserManagerEnvironmentDoesNotInheritHostileSessionValues(t *testing.T) {
	for _, assignment := range []string{
		"LD_PRELOAD=/tmp/attacker.so",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/attacker-bus",
		"SYSTEMD_PAGER=/tmp/attacker-pager",
		"SYSTEMD_COLORS=1",
		"XDG_CONFIG_HOME=/tmp/attacker-config",
		"GODEBUG=execerrdot=0",
	} {
		parts := strings.SplitN(assignment, "=", 2)
		t.Setenv(parts[0], parts[1])
	}
	environment, err := userManagerEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"XDG_RUNTIME_DIR=/run/user/" + strconv.Itoa(os.Geteuid()),
		"LANG=C", "LC_ALL=C", "SYSTEMD_PAGER=cat", "SYSTEMD_COLORS=0", "SYSTEMD_URLIFY=0",
	}
	if strings.Join(environment, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("trusted environment = %q, want %q", environment, want)
	}
}

func TestParseCgroupPopulatedRejectsMissingDuplicateMalformedAndOversized(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{value: "populated 0\nfrozen 0\n", want: false},
		{value: "populated 1\nfrozen 0\n", want: true},
	} {
		got, err := parseCgroupPopulated([]byte(test.value))
		if err != nil || got != test.want {
			t.Fatalf("parseCgroupPopulated(%q) = %v, %v", test.value, got, err)
		}
	}
	for _, value := range []string{"", "frozen 0", "populated max", "populated 0\npopulated 1", strings.Repeat("x", 4097)} {
		if _, err := parseCgroupPopulated([]byte(value)); err == nil {
			t.Errorf("parseCgroupPopulated accepted %q", value)
		}
	}
}

func TestWaitCgroupEmptyRequiresObservedEmptyState(t *testing.T) {
	directory := t.TempDir()
	events := filepath.Join(directory, "cgroup.events")
	if err := os.WriteFile(events, []byte("populated 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { done <- waitCgroupEmpty(ctx, directory) }()
	select {
	case err := <-done:
		t.Fatalf("returned before the cgroup was empty: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	replacement := filepath.Join(directory, "replacement.events")
	if err := os.WriteFile(replacement, []byte("populated 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, events); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("waitCgroupEmpty() = %v", err)
	}
}

func TestWaitCgroupEmptyFailsClosedAtDeadline(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "cgroup.events"), []byte("populated 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if err := waitCgroupEmpty(ctx, directory); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitCgroupEmpty() = %v, want deadline exceeded", err)
	}
}

func TestLiveSystemdScopeEnforcesVerifiableControls(t *testing.T) {
	if helperArgument("resource-helper") == "verify" {
		manager, err := DefaultManager()
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Verify(helperArgument("resource-unit")); err != nil {
			t.Fatal(err)
		}
		if err := manager.VerifyRuntime(context.Background(), helperArgument("resource-unit")); err != nil {
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
	// These values would redirect or inject into inherited systemd tools. The
	// live scope must still use the validated real user-manager connection.
	t.Setenv("LD_PRELOAD", "/definitely/missing/attacker.so")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/definitely/missing/attacker-bus")
	t.Setenv("SYSTEMD_PAGER", "/definitely/missing/attacker-pager")
	t.Setenv("XDG_CONFIG_HOME", "/definitely/missing/attacker-config")
	if err := manager.Run(context.Background(), unit, executable, []string{"-test.run=^TestLiveSystemdScopeEnforcesVerifiableControls$", "-resource-helper=verify", "-resource-unit=" + unit}); err != nil {
		t.Fatalf("live resource scope: %v", err)
	}
}

func TestLiveSystemdScopeEnforcesMemoryMax(t *testing.T) {
	if helperArgument("resource-helper") == "memory" {
		allocation := make([]byte, 320<<20)
		for index := 0; index < len(allocation); index += 4096 {
			allocation[index] = 1
		}
		runtime.KeepAlive(allocation)
		os.Exit(99)
	}
	manager, unit, executable := liveScopeTest(t)
	if err := manager.Run(context.Background(), unit, executable, []string{"-test.run=^TestLiveSystemdScopeEnforcesMemoryMax$", "-resource-helper=memory"}); err == nil {
		t.Fatal("memory exhaustion survived the systemd scope")
	}
}

func TestLiveSystemdScopeEnforcesTasksMax(t *testing.T) {
	if helperArgument("resource-helper") == "tasks" {
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
	if err := manager.Run(context.Background(), unit, executable, []string{"-test.run=^TestLiveSystemdScopeEnforcesTasksMax$", "-resource-helper=tasks"}); err != nil {
		t.Fatalf("task-limit helper failed: %v", err)
	}
}

func TestLiveSystemdScopeKillsSurvivingDescendant(t *testing.T) {
	if helperArgument("resource-helper") == "descendant" {
		child := exec.Command("/usr/bin/sleep", "30")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(helperArgument("descendant-pid"), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	manager, unit, executable := liveScopeTest(t)
	pidFile := filepath.Join(t.TempDir(), "descendant.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = manager.Run(ctx, unit, executable, []string{"-test.run=^TestLiveSystemdScopeKillsSurvivingDescendant$", "-resource-helper=descendant", "-descendant-pid=" + pidFile})
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read descendant pid: %v", err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(policy.TeardownTimeout)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("descendant pid %d survived scope teardown", pid)
}

func helperArgument(name string) string {
	switch name {
	case "resource-helper":
		return *resourceHelper
	case "resource-unit":
		return *resourceUnit
	case "descendant-pid":
		return *descendantPID
	}
	return ""
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
