package sandbox

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/policy"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/safetext"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/trustedexec"
)

const bubblewrapPath = "/usr/bin/bwrap"

const (
	MaxReportBytes = policy.MaxReportBytes
	MaxStderrBytes = 64 << 10
)

type Runner struct {
	Bubblewrap string
	Timeout    time.Duration
}

func DefaultRunner() (Runner, error) {
	bwrap, err := trustedexec.Require(bubblewrapPath)
	if err != nil {
		return Runner{}, fmt.Errorf("trusted bubblewrap is required; refusing to scan without containment: %w", err)
	}
	return Runner{Bubblewrap: bwrap, Timeout: policy.WallTime}, nil
}

func (r Runner) Run(ctx context.Context, scannerPath string, target *os.File, displayName string) ([]byte, error) {
	return r.RunWithAudit(ctx, scannerPath, target, displayName, "", "")
}

func (r Runner) RunWithAudit(ctx context.Context, scannerPath string, target *os.File, displayName, auditPath, auditFormat string) ([]byte, error) {
	if r.Bubblewrap == "" {
		return nil, errors.New("bubblewrap path is empty")
	}
	if r.Timeout <= 0 {
		return nil, errors.New("sandbox timeout must be positive")
	}
	if !validDisplayName(displayName) {
		return nil, errors.New("sandbox display name is invalid")
	}
	if target == nil {
		return nil, errors.New("pinned target descriptor is required")
	}
	if (auditPath == "") != (auditFormat == "") {
		return nil, errors.New("audit path and pinned format must be supplied together")
	}
	targetInfo, err := target.Stat()
	if err != nil || !targetInfo.IsDir() {
		return nil, errors.New("pinned target descriptor is not a directory")
	}
	scanner, err := openPinned(scannerPath, false)
	if err != nil {
		return nil, fmt.Errorf("pin scanner: %w", err)
	}
	defer scanner.Close()
	var audit *os.File
	if auditPath != "" {
		audit, err = openPinned(auditPath, false)
		if err != nil {
			return nil, fmt.Errorf("pin Omarchy audit: %w", err)
		}
		defer audit.Close()
	}
	if err := requireStaticELF(scanner); err != nil {
		return nil, fmt.Errorf("validate scanner executable: %w", err)
	}
	timed, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	arguments := Arguments("/proc/self/fd/3", "/proc/self/fd/4", displayName)
	if audit != nil {
		arguments = ArgumentsWithAudit("/proc/self/fd/3", "/proc/self/fd/4", displayName, "/proc/self/fd/5", auditFormat)
	}
	cmd := exec.CommandContext(timed, r.Bubblewrap, arguments...)
	cmd.ExtraFiles = []*os.File{scanner, target}
	if audit != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, audit)
	}
	cmd.Env = []string{}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("open scanner output: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("open scanner diagnostics: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start sandbox: %w", err)
	}

	type readResult struct {
		data []byte
		err  error
	}
	readBounded := func(reader io.Reader, limit int64) readResult {
		var buf bytes.Buffer
		_, copyErr := io.Copy(&buf, io.LimitReader(reader, limit+1))
		if copyErr != nil {
			return readResult{err: copyErr}
		}
		if int64(buf.Len()) > limit {
			return readResult{err: fmt.Errorf("output exceeded %d-byte limit", limit)}
		}
		return readResult{data: buf.Bytes()}
	}
	type streamResult struct {
		stdout bool
		readResult
	}
	results := make(chan streamResult, 2)
	go func() { results <- streamResult{stdout: true, readResult: readBounded(stdout, MaxReportBytes)} }()
	go func() { results <- streamResult{stdout: false, readResult: readBounded(stderr, MaxStderrBytes)} }()
	var out, diagnostics readResult
	for range 2 {
		result := <-results
		if result.stdout {
			out = result.readResult
		} else {
			diagnostics = result.readResult
		}
		if result.err != nil {
			cancel()
		}
	}
	waitErr := cmd.Wait()
	if out.err != nil {
		return nil, fmt.Errorf("read scanner output: %w", out.err)
	}
	if diagnostics.err != nil {
		return nil, fmt.Errorf("read scanner diagnostics: %w", diagnostics.err)
	}
	if errors.Is(timed.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("sandbox timed out after %s", r.Timeout)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("sandboxed scanner failed: %w: %s", waitErr, safetext.Diagnostic(diagnostics.data, MaxStderrBytes))
	}
	return out.data, nil
}

func requireStaticELF(scanner *os.File) error {
	parsed, err := elf.NewFile(scanner)
	if err != nil {
		return fmt.Errorf("scanner is not a supported ELF executable: %w", err)
	}
	defer parsed.Close()
	if parsed.Type != elf.ET_EXEC && parsed.Type != elf.ET_DYN {
		return fmt.Errorf("scanner ELF type %s is not executable", parsed.Type)
	}
	for _, program := range parsed.Progs {
		if program.Type == elf.PT_INTERP {
			return errors.New("scanner is dynamically linked; build it with CGO_ENABLED=0")
		}
	}
	libraries, err := parsed.ImportedLibraries()
	if err != nil {
		return fmt.Errorf("inspect scanner libraries: %w", err)
	}
	if len(libraries) != 0 {
		return fmt.Errorf("scanner imports shared libraries: %v", libraries)
	}
	return nil
}

func Arguments(scannerSource, targetSource, displayName string) []string {
	return []string{
		"--die-with-parent",
		"--new-session",
		"--unshare-all",
		"--unshare-user",
		"--disable-userns",
		"--assert-userns-disabled",
		"--cap-drop", "ALL",
		"--clearenv",
		"--setenv", "HOME", "/nonexistent",
		"--setenv", "PATH", "/app",
		"--setenv", "TMPDIR", "/tmp",
		"--dir", "/app",
		"--ro-bind", scannerSource, "/app/plug-prejudice",
		"--ro-bind", targetSource, "/target",
		"--dir", "/tmp",
		"--chdir", "/target",
		"--",
		"/app/plug-prejudice", "--target", "/target", "--display-name", displayName, "--sandboxed", "--resource-limited",
	}
}

func ArgumentsWithAudit(scannerSource, targetSource, displayName, auditSource, auditFormat string) []string {
	arguments := Arguments(scannerSource, targetSource, displayName)
	separator := 0
	for index, argument := range arguments {
		if argument == "--" {
			separator = index
			break
		}
	}
	prefix := append([]string(nil), arguments[:separator]...)
	prefix = append(prefix, "--dir", "/audit", "--ro-bind", auditSource, "/audit/omarchy.json")
	command := append([]string(nil), arguments[separator:]...)
	command = append(command, "--omarchy-audit", "/audit/omarchy.json", "--omarchy-audit-format", auditFormat)
	return append(prefix, command...)
}

func validDisplayName(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	for index, character := range value {
		if (character >= 'A' && character <= 'Z') ||
			(character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == '_' || character == '-')) {
			continue
		}
		return false
	}
	return !strings.Contains(value, "..")
}

func openPinned(name string, wantDirectory bool) (*os.File, error) {
	clean, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	linked, err := os.Lstat(clean)
	if err != nil {
		return nil, err
	}
	if linked.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("symbolic-link endpoints are not allowed")
	}
	if wantDirectory != linked.IsDir() {
		if wantDirectory {
			return nil, errors.New("target is not a directory")
		}
		return nil, errors.New("scanner is not a regular file")
	}
	if !wantDirectory && !linked.Mode().IsRegular() {
		return nil, errors.New("scanner is not a regular file")
	}
	f, err := os.Open(clean)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(linked, opened) {
		_ = f.Close()
		return nil, errors.New("path identity changed while being opened")
	}
	return f, nil
}
