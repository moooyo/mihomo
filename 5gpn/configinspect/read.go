package configinspect

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func readConfigFile(path string) ([]byte, error) {
	return readConfigFileForOwner(path, 0)
}

func readConfigFileForOwner(path string, expectedOwnerUID int) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("config path is required")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("config path must be absolute")
	}
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve config directory: %w", err)
	}
	if filepath.Clean(resolvedDir) != dir {
		return nil, fmt.Errorf("config directory must not contain symlinks")
	}

	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect config path: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("config must be a regular file and not a symlink")
	}
	if before.Size() > maxConfigBytes {
		return nil, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}

	file, err := openConfigNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("open config without following links: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened config: %w", err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("config changed while opening")
	}
	if err := requireSecureConfigMetadata(file, opened, expectedOwnerUID); err != nil {
		return nil, err
	}
	if err := requireSingleConfigLink(file, opened); err != nil {
		return nil, err
	}

	raw, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if len(raw) > maxConfigBytes {
		return nil, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("recheck opened config: %w", err)
	}
	if !os.SameFile(opened, after) || after.Size() != int64(len(raw)) ||
		after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return nil, fmt.Errorf("config changed while reading")
	}
	if err := requireSecureConfigMetadata(file, after, expectedOwnerUID); err != nil {
		return nil, err
	}
	if err := requireSingleConfigLink(file, after); err != nil {
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(after, current) ||
		current.Size() != after.Size() || !current.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("config changed while reading")
	}
	if err := requireSecureConfigMetadata(file, current, expectedOwnerUID); err != nil {
		return nil, err
	}
	if err := requireSingleConfigLink(file, current); err != nil {
		return nil, err
	}
	return raw, nil
}
