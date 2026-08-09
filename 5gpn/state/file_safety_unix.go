//go:build !windows

package state

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openPrivateNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func validatePrivatePathInfo(info os.FileInfo) error {
	return validatePrivateFileInfo(info)
}

func validatePrivateOpenFile(_ *os.File, info os.FileInfo) error {
	return validatePrivateFileInfo(info)
}

func validatePrivateFileInfo(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("could not inspect owner and link count")
	}
	if !privateFileOwnerMatches(stat, os.Geteuid()) {
		return errors.New("file is not owned by the current service identity")
	}
	if stat.Nlink != 1 {
		return errors.New("file must have exactly one hard link")
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("file has privileged mode bits")
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		return fmt.Errorf("file mode is %04o, want 0600", mode)
	}
	return nil
}

func privateFileOwnerMatches(stat *syscall.Stat_t, uid int) bool {
	return stat != nil && int(stat.Uid) == uid
}
