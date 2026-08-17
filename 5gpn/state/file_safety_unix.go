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

func validateExpectedPrivateFileOwner(expectedUID int) error {
	readerUID := os.Geteuid()
	if readerUID != 0 && readerUID != expectedUID {
		return errors.New("5gpn/state: only root may select a different expected file owner")
	}
	return nil
}

func validatePrivatePathInfo(info os.FileInfo, expectedUID *int) error {
	return validatePrivateFileInfo(info, expectedUID)
}

func validatePrivateOpenFile(_ *os.File, info os.FileInfo, expectedUID *int) error {
	return validatePrivateFileInfo(info, expectedUID)
}

func validatePrivateFileInfo(info os.FileInfo, expectedUID *int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("could not inspect owner and link count")
	}
	readerUID := os.Geteuid()
	if !privateFileOwnerMatches(stat, readerUID, expectedUID) {
		if expectedUID == nil {
			return errors.New("file is not owned by the current service identity")
		}
		if readerUID != 0 && readerUID != *expectedUID {
			return errors.New("only root may select a different expected file owner")
		}
		return fmt.Errorf("file owner UID is %d, want %d", stat.Uid, *expectedUID)
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

func privateFileOwnerMatches(stat *syscall.Stat_t, readerUID int, expectedUID *int) bool {
	if stat == nil {
		return false
	}
	if expectedUID == nil {
		return int(stat.Uid) == readerUID
	}
	if readerUID != 0 && readerUID != *expectedUID {
		return false
	}
	return int(stat.Uid) == *expectedUID
}
