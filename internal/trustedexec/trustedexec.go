package trustedexec

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

type Executable struct {
	file *os.File
}

func Open(path string) (*Executable, error) {
	return openOwned(path, 0)
}

func openOwned(path string, owner uint32) (*Executable, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("trusted executable path must be absolute")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("open trusted executable without symlinks: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("create trusted executable descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		_ = file.Close()
		return nil, errors.New("trusted executable ownership is unavailable")
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("trusted executable must be a regular file")
	}
	if info.Mode().Perm()&0o111 == 0 {
		_ = file.Close()
		return nil, errors.New("trusted executable is not executable")
	}
	if info.Mode().Perm()&0o022 != 0 {
		_ = file.Close()
		return nil, errors.New("trusted executable is group- or world-writable")
	}
	if stat.Uid != owner {
		_ = file.Close()
		return nil, fmt.Errorf("trusted executable is owned by uid %d, expected %d", stat.Uid, owner)
	}
	parsed, err := elf.NewFile(file)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("trusted executable is not an ELF binary: %w", err)
	}
	_ = parsed.Close()
	return &Executable{file: file}, nil
}

func (e *Executable) Close() error {
	if e == nil || e.file == nil {
		return nil
	}
	return e.file.Close()
}

func (e *Executable) File() *os.File {
	if e == nil {
		return nil
	}
	return e.file
}

func (e *Executable) CommandPath(arguments ...string) (string, []string, error) {
	if e == nil || e.file == nil {
		return "", nil, errors.New("trusted executable descriptor is unavailable")
	}
	// Linux resolves this procfd to the already-open inode during execve. The
	// descriptor remains present across fork and is closed atomically by
	// O_CLOEXEC only after that resolution, so later pathname replacement cannot
	// select a different executable.
	procPath := "/proc/self/fd/" + strconv.FormatUint(uint64(e.file.Fd()), 10)
	return procPath, arguments, nil
}
