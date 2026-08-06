//go:build !windows

package nodes

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func requireSingleLink(_ string, info os.FileInfo) error {
	return requireSingleLinkFile(nil, info)
}

func validateDirectoryOwnerAndMode(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not inspect config directory ownership")
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("config directory must be owned by the calling user")
	}
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("writable config directory must have the sticky bit")
	}
	return nil
}

func requireSingleLinkFile(_ *os.File, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not inspect file link count")
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("file must have exactly one hard link")
	}
	return nil
}

func openReadNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openLockNoFollow(path string) (*os.File, bool, error) {
	flags := unix.O_RDWR | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fd, err := unix.Open(path, flags, 0o600)
	if err == nil {
		return os.NewFile(uintptr(fd), path), true, nil
	}
	if err != unix.EEXIST {
		return nil, false, err
	}
	fd, err = unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false, err
	}
	return os.NewFile(uintptr(fd), path), false, nil
}

func secureLockOwnership(file *os.File, _ os.FileInfo, created bool) error {
	expectedUID := os.Geteuid()
	expectedGID := os.Getegid()
	lockInfo, err := file.Stat()
	if err != nil {
		return err
	}
	lockStat, ok := lockInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not inspect lock ownership")
	}
	if !created && !lockOwnerMatches(lockStat, expectedUID, expectedGID) {
		return fmt.Errorf("existing lock has an unexpected owner")
	}
	if created {
		if err := file.Chown(expectedUID, expectedGID); err != nil {
			return fmt.Errorf("secure lock ownership: %w", err)
		}
	}
	return nil
}

func lockOwnerMatches(stat *syscall.Stat_t, uid, gid int) bool {
	return stat != nil && int(stat.Uid) == uid && int(stat.Gid) == gid
}

func preserveOwnership(file *os.File, source os.FileInfo) error {
	stat, ok := source.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not inspect file ownership")
	}
	if err := file.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
		return fmt.Errorf("preserve file ownership: %w", err)
	}
	return nil
}
