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
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/trustedexec"
)

const bubblewrapPath = "/usr/bin/bwrap"

const (
	MaxReportBytes = 16 << 20
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

func (r Runner) Run(ctx context.Context, scannerPath, targetPath, displayName string) ([]byte, error) {
	if r.Bubblewrap == "" {
		return nil, errors.New("bubblewrap path is empty")
	}
	if r.Timeout <= 0 {
		return nil, errors.New("sandbox timeout must be positive")
	}
	if !validDisplayName(displayName) {
		return nil, errors.New("sandbox display name is invalid")
	}
	scanner, err := openPinned(scannerPath, false)
	if err != nil {
		return nil, fmt.Errorf("pin scanner: %w", err)
	}
	defer scanner.Close()
	if err := requireStaticELF(scanner); err != nil {
		return nil, fmt.Errorf("validate scanner executable: %w", err)
	}
	target, err := openPinned(targetPath, true)
	if err != nil {
		return nil, fmt.Errorf("pin target: %w", err)
	}
	defer target.Close()

	timed, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(timed, r.Bubblewrap, Arguments("/proc/self/fd/3", "/proc/self/fd/4", displayName)...)
	cmd.ExtraFiles = []*os.File{scanner, target}
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
	outCh := make(chan readResult, 1)
	errCh := make(chan readResult, 1)
	go func() { outCh <- readBounded(stdout, MaxReportBytes) }()
	go func() { errCh <- readBounded(stderr, MaxStderrBytes) }()
	out := <-outCh
	if out.err != nil {
		cancel()
	}
	diagnostics := <-errCh
	if diagnostics.err != nil {
		cancel()
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
		return nil, fmt.Errorf("sandboxed scanner failed: %w: %s", waitErr, safeDiagnostic(diagnostics.data))
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

func safeDiagnostic(data []byte) string {
	const replacement = '?'
	runes := []rune(string(data))
	for i, value := range runes {
		if value < 0x20 && value != '\n' && value != '\t' {
			runes[i] = replacement
		}
	}
	return string(runes)
}
