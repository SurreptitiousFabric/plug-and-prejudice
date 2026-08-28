package trustedexec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func Require(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("trusted executable path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("trusted executable must be a non-symlink regular file")
	}
	if info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("trusted executable is not executable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("trusted executable ownership is unavailable")
	}
	if stat.Uid != 0 {
		return "", fmt.Errorf("trusted executable is owned by uid %d, expected root", stat.Uid)
	}
	return path, nil
}
