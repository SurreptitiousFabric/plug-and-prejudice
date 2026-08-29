package resource

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/policy"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/trustedexec"
	"golang.org/x/sys/unix"
)

const (
	systemdRunPath = "/usr/bin/systemd-run"
	systemctlPath  = "/usr/bin/systemctl"
)

type Manager struct {
	SystemdRun string
	Systemctl  string
	CgroupRoot string
	ProcCgroup string
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
}

type operationDeadlines struct {
	operationEnd time.Time
	runEnd       time.Time
}

func deadlinesFor(start time.Time) operationDeadlines {
	operationEnd := start.Add(policy.OperationTimeout)
	return operationDeadlines{
		operationEnd: operationEnd,
		runEnd:       operationEnd.Add(-(policy.TeardownTimeout + 2*policy.ProcessWaitDelay)),
	}
}

func DefaultManager() (Manager, error) {
	systemdRun, err := trustedexec.Open(systemdRunPath)
	if err != nil {
		return Manager{}, fmt.Errorf("trusted systemd-run is required; refusing to scan without resource containment: %w", err)
	}
	defer systemdRun.Close()
	systemctl, err := trustedexec.Open(systemctlPath)
	if err != nil {
		return Manager{}, fmt.Errorf("trusted systemctl is required; refusing to scan without lifetime verification: %w", err)
	}
	defer systemctl.Close()
	return Manager{SystemdRun: systemdRunPath, Systemctl: systemctlPath, CgroupRoot: "/sys/fs/cgroup", ProcCgroup: "/proc/self/cgroup"}, nil
}

func NewUnitName() (string, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate scope nonce: %w", err)
	}
	return "plug-prejudice-" + hex.EncodeToString(nonce[:]) + ".scope", nil
}

func (m Manager) Run(ctx context.Context, unit, executable string, arguments []string) error {
	if m.SystemdRun == "" {
		return errors.New("systemd-run path is empty")
	}
	if !validUnitName(unit) {
		return errors.New("resource scope unit name is invalid")
	}
	systemdRun, err := trustedexec.Open(m.SystemdRun)
	if err != nil {
		return fmt.Errorf("pin systemd-run: %w", err)
	}
	defer systemdRun.Close()
	procPath, args, err := systemdRun.CommandPath(Arguments(unit, executable, arguments)...)
	if err != nil {
		return err
	}
	if !policy.ValidTimingPolicy() {
		return errors.New("resource timing policy is internally inconsistent")
	}
	deadlines := deadlinesFor(time.Now())
	runContext, cancelRun := context.WithDeadline(ctx, deadlines.runEnd)
	defer cancelRun()
	cmd := exec.CommandContext(runContext, procPath, args...)
	cmd.WaitDelay = policy.ProcessWaitDelay
	cmd.Stdin = m.Stdin
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	cmd.Stdout = m.Stdout
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	cmd.Stderr = m.Stderr
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	cmd.Env, err = userManagerEnvironment()
	if err != nil {
		return fmt.Errorf("construct trusted systemd-run environment: %w", err)
	}
	runErr := cmd.Run()
	teardownEnd := minTime(deadlines.operationEnd.Add(-policy.ProcessWaitDelay), time.Now().Add(policy.TeardownTimeout))
	teardownContext, cancelTeardown := context.WithDeadline(context.WithoutCancel(ctx), teardownEnd)
	teardownErr := m.Terminate(teardownContext, unit)
	cancelTeardown()
	if runErr != nil {
		if teardownErr != nil {
			return errors.Join(runErr, teardownErr)
		}
		return runErr
	}
	return teardownErr
}

func Arguments(unit, executable string, arguments []string) []string {
	result := []string{
		"--user", "--scope", "--unit", unit, "--quiet", "--collect",
		"--property=MemoryAccounting=yes",
		fmt.Sprintf("--property=MemoryMax=%d", policy.MemoryMaxBytes),
		fmt.Sprintf("--property=MemorySwapMax=%d", policy.MemorySwapBytes),
		"--property=TasksAccounting=yes",
		fmt.Sprintf("--property=TasksMax=%d", policy.TasksMax),
		fmt.Sprintf("--property=CPUQuota=%d%%", policy.CPUQuotaPercent),
		fmt.Sprintf("--property=RuntimeMaxSec=%s", policy.ScopeRuntime),
		"--", executable,
	}
	return append(result, arguments...)
}

func (m Manager) Verify(unit string) error {
	if !validUnitName(unit) {
		return errors.New("resource scope unit name is invalid")
	}
	data, err := os.ReadFile(m.ProcCgroup)
	if err != nil {
		return fmt.Errorf("read current cgroup: %w", err)
	}
	cgroupPath, err := unifiedCgroupPath(string(data))
	if err != nil {
		return err
	}
	if filepath.Base(cgroupPath) != unit {
		return fmt.Errorf("current cgroup %q is not expected scope %q", cgroupPath, unit)
	}
	root, err := filepath.Abs(m.CgroupRoot)
	if err != nil {
		return fmt.Errorf("resolve cgroup root: %w", err)
	}
	directory := filepath.Join(root, strings.TrimPrefix(filepath.Clean(cgroupPath), string(filepath.Separator)))
	if directory != root && !strings.HasPrefix(directory, root+string(filepath.Separator)) {
		return errors.New("current cgroup escapes cgroup root")
	}
	checks := []struct {
		name string
		max  int64
	}{
		{name: "memory.max", max: policy.MemoryMaxBytes},
		{name: "memory.swap.max", max: policy.MemorySwapBytes},
		{name: "pids.max", max: policy.TasksMax},
	}
	for _, check := range checks {
		value, readErr := readLimit(filepath.Join(directory, check.name))
		if readErr != nil {
			return fmt.Errorf("verify %s: %w", check.name, readErr)
		}
		if value < 0 || value > check.max {
			return fmt.Errorf("%s is %d, expected at most %d", check.name, value, check.max)
		}
	}
	cpu, err := os.ReadFile(filepath.Join(directory, "cpu.max"))
	if err != nil {
		return fmt.Errorf("verify cpu.max: %w", err)
	}
	fields := strings.Fields(string(cpu))
	if len(fields) != 2 || fields[0] == "max" {
		return fmt.Errorf("cpu.max is not bounded: %q", strings.TrimSpace(string(cpu)))
	}
	quota, quotaErr := strconv.ParseInt(fields[0], 10, 64)
	period, periodErr := strconv.ParseInt(fields[1], 10, 64)
	if quotaErr != nil || periodErr != nil || quota <= 0 || period <= 0 || policy.CPUQuotaPercent != 100 || quota > period {
		return fmt.Errorf("cpu.max exceeds %d%%: %q", policy.CPUQuotaPercent, strings.TrimSpace(string(cpu)))
	}
	return nil
}

func (m Manager) VerifyRuntime(ctx context.Context, unit string) error {
	if !validUnitName(unit) {
		return errors.New("resource scope unit name is invalid")
	}
	timed, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	output, err := m.systemctl(timed, "show", unit, "--property=RuntimeMaxUSec", "--value", "--no-pager")
	if err != nil {
		return fmt.Errorf("query live scope lifetime: %w", err)
	}
	if len(output) > 128 {
		return errors.New("live scope lifetime response exceeds limit")
	}
	return verifyRuntimeMax(string(output))
}

func verifyRuntimeMax(value string) error {
	text := strings.TrimSuffix(value, "\n")
	if strings.Contains(text, "\n") || !runtimeDurationPattern.MatchString(text) {
		return fmt.Errorf("RuntimeMaxUSec is %q, expected supported systemd duration syntax", value)
	}
	duration, err := time.ParseDuration(text)
	if err != nil || duration <= 0 || duration > policy.ScopeRuntime {
		return fmt.Errorf("RuntimeMaxUSec is %q, expected at most %s", text, policy.ScopeRuntime)
	}
	return nil
}

var runtimeDurationPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?(?:us|ms|s)$`)

func (m Manager) Terminate(ctx context.Context, unit string) error {
	if !validUnitName(unit) {
		return errors.New("resource scope unit name is invalid")
	}
	teardown, cancel := context.WithTimeout(ctx, policy.TeardownTimeout)
	defer cancel()

	loadState, err := m.systemctl(teardown, "show", unit, "--property=LoadState", "--value", "--no-pager")
	if err != nil {
		return fmt.Errorf("query resource scope before teardown: %w", err)
	}
	if len(loadState) > 128 {
		return errors.New("resource scope LoadState response exceeds limit")
	}
	if strings.TrimSpace(string(loadState)) == "not-found" {
		return nil
	}
	controlGroup, err := m.systemctl(teardown, "show", unit, "--property=ControlGroup", "--value", "--no-pager")
	if err != nil {
		return fmt.Errorf("query resource scope cgroup: %w", err)
	}
	if len(controlGroup) > 4096 {
		return errors.New("resource scope ControlGroup response exceeds limit")
	}
	controlGroupText := strings.TrimSpace(string(controlGroup))
	if controlGroupText == "" {
		activeState, stateErr := m.systemctl(teardown, "show", unit, "--property=ActiveState", "--value", "--no-pager")
		if stateErr == nil && len(activeState) <= 128 && terminalStateWithoutControlGroup(strings.TrimSpace(string(loadState)), strings.TrimSpace(string(activeState))) {
			return nil
		}
		return errors.New("resource scope has no ControlGroup but is not confirmed inactive")
	}
	directory, err := m.cgroupDirectory(unit, controlGroupText)
	if err != nil {
		return fmt.Errorf("validate resource scope cgroup: %w", err)
	}

	killContext, killCancel := context.WithTimeout(teardown, policy.TeardownCommandTimeout)
	_, killErr := m.systemctl(killContext, "kill", unit, "--kill-whom=all", "--signal=KILL", "--no-block")
	killCancel()
	waitErr := waitCgroupEmpty(teardown, directory)
	return teardownResult(killErr, waitErr)
}

func terminalStateWithoutControlGroup(loadState, activeState string) bool {
	return loadState == "loaded" && (activeState == "inactive" || activeState == "failed")
}

func teardownResult(killErr, waitErr error) error {
	if waitErr == nil {
		return nil
	}
	if killErr != nil {
		return errors.Join(fmt.Errorf("request whole-scope termination: %w", killErr), waitErr)
	}
	return fmt.Errorf("verify whole-scope termination: %w", waitErr)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (m Manager) systemctl(ctx context.Context, arguments ...string) ([]byte, error) {
	if m.Systemctl == "" {
		return nil, errors.New("systemctl path is empty")
	}
	systemctl, err := trustedexec.Open(m.Systemctl)
	if err != nil {
		return nil, fmt.Errorf("pin systemctl: %w", err)
	}
	defer systemctl.Close()
	procPath, args, err := systemctl.CommandPath(append([]string{"--user"}, arguments...)...)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, procPath, args...)
	cmd.WaitDelay = policy.ProcessWaitDelay
	cmd.Env, err = userManagerEnvironment()
	if err != nil {
		return nil, fmt.Errorf("construct trusted systemctl environment: %w", err)
	}
	return cmd.Output()
}

func userManagerEnvironment() ([]string, error) {
	runtimeDirectory := "/run/user/" + strconv.Itoa(os.Geteuid())
	fd, err := unix.Openat2(unix.AT_FDCWD, runtimeDirectory, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("open user runtime directory: %w", err)
	}
	file := os.NewFile(uintptr(fd), runtimeDirectory)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("create user runtime directory descriptor")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect user runtime directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("user runtime directory has unsafe ownership, type, or mode")
	}
	return []string{
		"XDG_RUNTIME_DIR=" + runtimeDirectory,
		"LANG=C",
		"LC_ALL=C",
		"SYSTEMD_PAGER=cat",
		"SYSTEMD_COLORS=0",
		"SYSTEMD_URLIFY=0",
	}, nil
}

func (m Manager) cgroupDirectory(unit, cgroupPath string) (string, error) {
	if cgroupPath == "" || !filepath.IsAbs(cgroupPath) || filepath.Clean(cgroupPath) != cgroupPath || filepath.Base(cgroupPath) != unit {
		return "", errors.New("scope ControlGroup is empty, malformed, or does not match the expected unit")
	}
	root, err := filepath.Abs(m.CgroupRoot)
	if err != nil {
		return "", fmt.Errorf("resolve cgroup root: %w", err)
	}
	directory := filepath.Join(root, strings.TrimPrefix(cgroupPath, string(filepath.Separator)))
	if directory == root || !strings.HasPrefix(directory, root+string(filepath.Separator)) {
		return "", errors.New("scope ControlGroup escapes cgroup root")
	}
	return directory, nil
}

func waitCgroupEmpty(ctx context.Context, directory string) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(filepath.Join(directory, "cgroup.events"))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		populated, err := parseCgroupPopulated(data)
		if err != nil {
			return err
		}
		if !populated {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func parseCgroupPopulated(data []byte) (bool, error) {
	if len(data) > 4096 {
		return false, errors.New("cgroup.events exceeds limit")
	}
	found := false
	populated := false
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			if found || (fields[1] != "0" && fields[1] != "1") {
				return false, errors.New("cgroup.events has malformed or duplicate populated state")
			}
			found = true
			populated = fields[1] == "1"
		}
	}
	if !found {
		return false, errors.New("cgroup.events omits populated state")
	}
	return populated, nil
}

func ApplyProcessLimits() error {
	limits := []struct {
		resource int
		value    uint64
	}{
		{resource: syscall.RLIMIT_CORE, value: 0},
		{resource: syscall.RLIMIT_NOFILE, value: policy.OpenFilesMax},
	}
	for _, limit := range limits {
		var current syscall.Rlimit
		if err := syscall.Getrlimit(limit.resource, &current); err != nil {
			return fmt.Errorf("read process resource limit %d: %w", limit.resource, err)
		}
		current.Cur = min(current.Cur, limit.value)
		current.Max = min(current.Max, limit.value)
		if current.Cur > current.Max {
			current.Cur = current.Max
		}
		if err := syscall.Setrlimit(limit.resource, &current); err != nil {
			return fmt.Errorf("set process resource limit %d: %w", limit.resource, err)
		}
	}
	return nil
}

func unifiedCgroupPath(data string) (string, error) {
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "0::/") {
			return strings.TrimPrefix(line, "0::"), nil
		}
	}
	return "", errors.New("unified cgroup v2 path is unavailable")
}

func readLimit(name string) (int64, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return 0, err
	}
	text := strings.TrimSpace(string(data))
	if text == "max" {
		return -1, nil
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %q: %w", text, err)
	}
	return value, nil
}

func validUnitName(unit string) bool {
	if !strings.HasPrefix(unit, "plug-prejudice-") || !strings.HasSuffix(unit, ".scope") {
		return false
	}
	nonce := strings.TrimSuffix(strings.TrimPrefix(unit, "plug-prejudice-"), ".scope")
	if len(nonce) != 24 {
		return false
	}
	_, err := hex.DecodeString(nonce)
	return err == nil
}
