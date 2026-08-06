//go:build windows

package nodes

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func requireSingleLink(path string, _ os.FileInfo) error {
	file, err := openReadNoFollow(path)
	if err != nil {
		return fmt.Errorf("inspect file link count: %w", err)
	}
	defer file.Close()
	return requireSingleLinkFile(file, nil)
}

func validateDirectoryOwnerAndMode(_ os.FileInfo) error { return nil }

func requireSingleLinkFile(file *os.File, _ os.FileInfo) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &information); err != nil {
		return fmt.Errorf("inspect file link count: %w", err)
	}
	if information.NumberOfLinks != 1 {
		return fmt.Errorf("file must have exactly one hard link")
	}
	return nil
}

func openReadNoFollow(path string) (*os.File, error) {
	return openWindowsNoFollow(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.OPEN_EXISTING)
}

func openLockNoFollow(path string) (*os.File, bool, error) {
	file, err := openWindowsNoFollow(path, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.CREATE_NEW)
	if err == nil {
		return file, true, nil
	}
	if !errors.Is(err, windows.ERROR_FILE_EXISTS) && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, false, err
	}
	file, err = openWindowsNoFollow(path, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.OPEN_EXISTING)
	return file, false, err
}

func openWindowsNoFollow(path string, access, share, disposition uint32) (*os.File, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		access,
		share,
		nil,
		disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		file.Close()
		return nil, err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		file.Close()
		return nil, fmt.Errorf("path is a reparse point")
	}
	return file, nil
}

func preserveOwnership(_ *os.File, _ os.FileInfo) error { return nil }

func secureLockOwnership(_ *os.File, _ os.FileInfo, _ bool) error { return nil }
