package nodes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func validateParentDirectory(dir string) error {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("resolve config directory: %w", err)
	}
	if filepath.Clean(resolved) != filepath.Clean(dir) {
		return fmt.Errorf("config directory must not contain symlinks")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect config directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("config parent must be a real directory")
	}
	return validateDirectoryOwnerAndMode(info)
}

func requireSafeExistingFile(path, label string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file and not a symlink", label)
	}
	if err := requireSingleLink(path, info); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}
