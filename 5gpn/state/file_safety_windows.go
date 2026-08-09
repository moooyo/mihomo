//go:build windows

package state

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func openPrivateNoFollow(path string) (*os.File, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
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
		return nil, errors.New("path is a reparse point")
	}
	return file, nil
}

func validatePrivatePathInfo(_ os.FileInfo) error { return nil }

func validatePrivateOpenFile(file *os.File, _ os.FileInfo) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &information); err != nil {
		return fmt.Errorf("inspect file link count: %w", err)
	}
	if information.NumberOfLinks != 1 {
		return errors.New("file must have exactly one hard link")
	}
	return nil
}
