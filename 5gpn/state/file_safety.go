package state

import (
	"errors"
	"fmt"
	"os"
)

// ReadPrivateFile opens one bounded private state file without following the
// final path component. Unix additionally requires the current service owner,
// mode 0600, and one hard link; Windows applies the equivalent regular-file,
// reparse-point, identity, and link-count checks available from a handle.
func ReadPrivateFile(path string, maxBytes int64) ([]byte, error) {
	return readPrivateFile(path, maxBytes, nil)
}

// ReadPrivateFileForOwner opens one bounded private state file while requiring
// an explicit Unix owner UID. Unix permits this override only to root or to the
// named owner itself; mode 0600, one hard link, and no-follow checks remain
// mandatory. Windows rejects the Unix-owner override.
func ReadPrivateFileForOwner(path string, maxBytes int64, expectedUID int) ([]byte, error) {
	if err := ValidatePrivateFileOwnerAccess(expectedUID); err != nil {
		return nil, err
	}
	return readPrivateFile(path, maxBytes, &expectedUID)
}

// ValidatePrivateFileOwnerAccess checks whether the current process may name
// expectedUID for ReadPrivateFileForOwner without touching the filesystem.
func ValidatePrivateFileOwnerAccess(expectedUID int) error {
	if expectedUID < 0 || uint64(expectedUID) > uint64(^uint32(0)) {
		return errors.New("5gpn/state: expected owner UID is outside the Unix UID range")
	}
	return validateExpectedPrivateFileOwner(expectedUID)
}

func readPrivateFile(path string, maxBytes int64, expectedUID *int) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("5gpn/state: file byte limit must be positive")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("5gpn/state: %s is not a regular file", path)
	}
	if err := validatePrivatePathInfo(pathInfo, expectedUID); err != nil {
		return nil, fmt.Errorf("5gpn/state: unsafe %s: %w", path, err)
	}
	// On Windows the identity backing FileInfo is resolved lazily. Comparing it
	// with itself pins that identity before the pathname can change.
	if !os.SameFile(pathInfo, pathInfo) {
		return nil, fmt.Errorf("5gpn/state: could not establish %s identity", path)
	}
	if pathInfo.Size() > maxBytes {
		return nil, fmt.Errorf("5gpn/state: %s exceeds %d bytes", path, maxBytes)
	}

	file, err := openPrivateNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("5gpn/state: open %s without following links: %w", path, err)
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("5gpn/state: inspect opened %s: %w", path, err)
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("5gpn/state: opened %s is not a regular file", path)
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return nil, fmt.Errorf("5gpn/state: %s changed while opening", path)
	}
	if err := validatePrivateOpenFile(file, openedInfo, expectedUID); err != nil {
		return nil, fmt.Errorf("5gpn/state: unsafe %s: %w", path, err)
	}
	if openedInfo.Size() > maxBytes {
		return nil, fmt.Errorf("5gpn/state: %s exceeds %d bytes", path, maxBytes)
	}

	// Check the name again after opening. The no-follow open protects the final
	// component; this closes the remaining rename window before bytes are used.
	currentInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("5gpn/state: recheck %s: %w", path, err)
	}
	if !currentInfo.Mode().IsRegular() || !os.SameFile(openedInfo, currentInfo) {
		return nil, fmt.Errorf("5gpn/state: %s changed while opening", path)
	}
	if err := validatePrivatePathInfo(currentInfo, expectedUID); err != nil {
		return nil, fmt.Errorf("5gpn/state: unsafe %s: %w", path, err)
	}

	raw, err := readAllBounded(file, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("5gpn/state: read %s: %w", path, err)
	}
	finalInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("5gpn/state: inspect read %s: %w", path, err)
	}
	if err := validatePrivateOpenFile(file, finalInfo, expectedUID); err != nil {
		return nil, fmt.Errorf("5gpn/state: unsafe %s after read: %w", path, err)
	}
	if finalInfo.Size() != int64(len(raw)) {
		return nil, fmt.Errorf("5gpn/state: %s changed while reading", path)
	}
	finalPathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("5gpn/state: final recheck %s: %w", path, err)
	}
	if !finalPathInfo.Mode().IsRegular() || !os.SameFile(finalInfo, finalPathInfo) {
		return nil, fmt.Errorf("5gpn/state: %s changed while reading", path)
	}
	if err := validatePrivatePathInfo(finalPathInfo, expectedUID); err != nil {
		return nil, fmt.Errorf("5gpn/state: unsafe %s after read: %w", path, err)
	}
	return raw, nil
}
