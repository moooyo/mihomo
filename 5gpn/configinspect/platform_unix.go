//go:build !windows

package configinspect

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func requireConfigInspectionIdentity(expectedOwnerUID int, containerOwnerMode bool) error {
	return validateConfigInspectionIdentity(os.Geteuid(), expectedOwnerUID, containerOwnerMode)
}

func validateConfigInspectionIdentity(currentUID, expectedOwnerUID int, containerOwnerMode bool) error {
	if containerOwnerMode {
		if expectedOwnerUID != containerConfigOwnerUID || currentUID != containerConfigOwnerUID {
			return fmt.Errorf("container controller config inspection requires UID %d", containerConfigOwnerUID)
		}
		return nil
	}
	if expectedOwnerUID != 0 || currentUID != 0 {
		return fmt.Errorf("controller config inspection requires root")
	}
	return nil
}

func openConfigNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func requireSecureConfigMetadata(_ *os.File, info os.FileInfo, expectedOwnerUID int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not inspect config ownership")
	}
	if uint64(stat.Uid) != uint64(expectedOwnerUID) {
		return fmt.Errorf("config owner does not match the expected identity")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("config must not be writable by group or others")
	}
	return nil
}

func requireSingleConfigLink(_ *os.File, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not inspect config link count")
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("config must have exactly one hard link")
	}
	return nil
}
