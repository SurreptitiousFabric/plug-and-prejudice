package resource

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/policy"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/trustedexec"
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
}

func DefaultManager() (Manager, error) {
	systemdRun, err := trustedexec.Require(systemdRunPath)
	if err != nil {
		return Manager{}, fmt.Errorf("trusted systemd-run is required; refusing to scan without resource containment: %w", err)
	}
	systemctl, err := trustedexec.Require(systemctlPath)
	if err != nil {
		return Manager{}, fmt.Errorf("trusted systemctl is required; refusing to scan without lifetime verification: %w", err)
	}
	return Manager{SystemdRun: systemdRun, Systemctl: systemctl, CgroupRoot: "/sys/fs/cgroup", ProcCgroup: "/proc/self/cgroup"}, nil
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
	cmd := exec.CommandContext(ctx, m.SystemdRun, Arguments(unit, executable, arguments)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
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
	if m.Systemctl == "" {
		return errors.New("systemctl path is empty")
	}
	timed, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(timed, m.Systemctl, "--user", "show", unit, "--property=RuntimeMaxUSec", "--value", "--no-pager")
	cmd.Env = os.Environ()
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("query live scope lifetime: %w", err)
	}
	if len(output) > 128 {
		return errors.New("live scope lifetime response exceeds limit")
	}
	return verifyRuntimeMax(string(output))
}

func verifyRuntimeMax(value string) error {
	text := strings.TrimSpace(value)
	duration, err := time.ParseDuration(text)
	if err != nil || duration <= 0 || duration > policy.ScopeRuntime {
		return fmt.Errorf("RuntimeMaxUSec is %q, expected at most %s", text, policy.ScopeRuntime)
	}
	return nil
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
