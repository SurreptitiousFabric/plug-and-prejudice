package sandbox

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/policy"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/trustedexec"
	"golang.org/x/sys/unix"
)

const bubblewrapPath = "/usr/bin/bwrap"

const (
	MaxReportBytes = 16 << 20
	MaxStderrBytes = 64 << 10
)

type Runner struct {
	Bubblewrap              string
	Timeout                 time.Duration
	AllowDevelopmentScanner bool
}

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
	cancel context.CancelFunc
	err    error
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	remaining := b.limit - b.buffer.Len()
	if len(data) <= remaining {
		return b.buffer.Write(data)
	}
	if remaining > 0 {
		_, _ = b.buffer.Write(data[:remaining])
	}
	b.err = fmt.Errorf("output exceeded %d-byte limit", b.limit)
	b.cancel()
	return remaining, b.err
}

func DefaultRunner() (Runner, error) {
	bwrap, err := trustedexec.Open(bubblewrapPath)
	if err != nil {
		return Runner{}, fmt.Errorf("trusted bubblewrap is required; refusing to scan without containment: %w", err)
	}
	defer bwrap.Close()
	return Runner{Bubblewrap: bubblewrapPath, Timeout: policy.WallTime}, nil
}

func (r Runner) Run(ctx context.Context, scannerPath string, target *os.File, displayName string) ([]byte, error) {
	if r.Bubblewrap == "" {
		return nil, errors.New("bubblewrap path is empty")
	}
	if r.Timeout <= 0 {
		return nil, errors.New("sandbox timeout must be positive")
	}
	if !validDisplayName(displayName) {
		return nil, errors.New("sandbox display name is invalid")
	}
	var scanner *os.File
	var trustedScanner *trustedexec.Executable
	var err error
	if r.AllowDevelopmentScanner {
		scanner, err = openPinned(scannerPath, false)
	} else {
		trustedScanner, err = trustedexec.Open(scannerPath)
		if err == nil {
			scanner = trustedScanner.File()
		}
	}
	if err != nil {
		return nil, fmt.Errorf("pin trusted scanner: %w", err)
	}
	if trustedScanner != nil {
		defer trustedScanner.Close()
	} else {
		defer scanner.Close()
	}
	if err := requireStaticELF(scanner); err != nil {
		return nil, fmt.Errorf("validate scanner executable: %w", err)
	}
	if target == nil {
		return nil, errors.New("pinned target descriptor is required")
	}
	targetInfo, err := target.Stat()
	if err != nil || !targetInfo.IsDir() {
		return nil, errors.New("pinned target descriptor is not a directory")
	}

	timed, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	bwrap, err := trustedexec.Open(r.Bubblewrap)
	if err != nil {
		return nil, fmt.Errorf("pin bubblewrap: %w", err)
	}
	defer bwrap.Close()
	procPath, args, err := bwrap.CommandPath(Arguments("/proc/self/fd/3", "/proc/self/fd/4", displayName)...)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(timed, procPath, args...)
	cmd.WaitDelay = policy.ProcessWaitDelay
	cmd.ExtraFiles = []*os.File{scanner, target}
	cmd.Env = []string{}
	out := &boundedBuffer{limit: MaxReportBytes, cancel: cancel}
	diagnostics := &boundedBuffer{limit: MaxStderrBytes, cancel: cancel}
	cmd.Stdout = out
	cmd.Stderr = diagnostics
	waitErr := cmd.Run()
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
		return nil, fmt.Errorf("sandboxed scanner failed: %w: %s", waitErr, safeDiagnostic(diagnostics.buffer.Bytes()))
	}
	return out.buffer.Bytes(), nil
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
	flags := uint64(unix.O_RDONLY | unix.O_CLOEXEC)
	if wantDirectory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, clean, &unix.OpenHow{
		Flags:   flags,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), clean)
	opened, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink == 0 || wantDirectory != opened.IsDir() || (!wantDirectory && !opened.Mode().IsRegular()) {
		_ = f.Close()
		return nil, errors.New("opened descriptor has unexpected type or identity")
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
