package nodes

import (
	"fmt"
	"os"
	"path/filepath"
)

type fileLock struct {
	file *os.File
}

func acquireFileLock(path string, configInfo os.FileInfo) (*fileLock, error) {
	if err := validateParentDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	file, created, err := openLockNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("open node-management lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("inspect node-management lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("node-management lock must be a regular file")
	}
	if err := requireSingleLinkFile(file, info); err != nil {
		file.Close()
		return nil, fmt.Errorf("node-management lock: %w", err)
	}
	if err := secureLockOwnership(file, configInfo, created); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("secure node-management lock: %w", err)
	}
	if err := lockFile(file); err != nil {
		file.Close()
		return nil, fmt.Errorf("lock node-management transaction: %w", err)
	}
	locked := &fileLock{file: file}
	info, err = file.Stat()
	if err != nil {
		locked.Close()
		return nil, fmt.Errorf("inspect node-management lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		locked.Close()
		return nil, fmt.Errorf("node-management lock must remain a regular file")
	}
	if err := requireSingleLinkFile(file, info); err != nil {
		locked.Close()
		return nil, fmt.Errorf("node-management lock: %w", err)
	}
	if err := secureLockOwnership(file, configInfo, false); err != nil {
		locked.Close()
		return nil, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		locked.Close()
		return nil, fmt.Errorf("node-management lock changed while it was opened")
	}
	return locked, nil
}

func (l *fileLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unlockFile(l.file)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
