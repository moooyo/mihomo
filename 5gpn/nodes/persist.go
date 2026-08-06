package nodes

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func persistPreviousAndConfig(configPath, backupPath string, previous, candidate []byte, sourceInfo os.FileInfo) error {
	if filepath.Dir(configPath) != filepath.Dir(backupPath) {
		return fmt.Errorf("config and previous backup must share a directory")
	}
	if err := validateParentDirectory(filepath.Dir(configPath)); err != nil {
		return err
	}
	if err := requireSafeExistingFile(backupPath, "node-management backup"); err != nil {
		return err
	}
	dir := filepath.Dir(configPath)
	backupTemp, err := stageFile(dir, filepath.Base(backupPath), previous, sourceInfo)
	if err != nil {
		return err
	}
	defer os.Remove(backupTemp)
	candidateTemp, err := stageFile(dir, filepath.Base(configPath), candidate, sourceInfo)
	if err != nil {
		return err
	}
	defer os.Remove(candidateTemp)
	rollbackTemp, err := stageFile(dir, filepath.Base(configPath)+".rollback", previous, sourceInfo)
	if err != nil {
		return err
	}
	defer os.Remove(rollbackTemp)

	if err := syncDirectory(dir); err != nil {
		return err
	}
	current, _, err := readRegularFile(configPath)
	if err != nil {
		return err
	}
	currentRevision := revisionOf(current)
	if currentRevision != revisionOf(previous) {
		return &RevisionConflictError{Current: currentRevision}
	}
	if err := os.Rename(backupTemp, backupPath); err != nil {
		return fmt.Errorf("publish previous config backup: %w", err)
	}
	backupTemp = ""
	if err := syncDirectory(dir); err != nil {
		return err
	}

	current, _, err = readRegularFile(configPath)
	if err != nil {
		return err
	}
	currentRevision = revisionOf(current)
	if currentRevision != revisionOf(previous) {
		return &RevisionConflictError{Current: currentRevision}
	}
	if err := os.Rename(candidateTemp, configPath); err != nil {
		return fmt.Errorf("publish candidate config: %w", err)
	}
	candidateTemp = ""
	if err := syncDirectory(dir); err != nil {
		publishErr := err
		if rollbackErr := os.Rename(rollbackTemp, configPath); rollbackErr != nil {
			return fmt.Errorf("publish candidate config: %v; restore previous bytes: %w", publishErr, rollbackErr)
		}
		rollbackTemp = ""
		if rollbackSyncErr := syncDirectory(dir); rollbackSyncErr != nil {
			return fmt.Errorf("publish candidate config: %v; persist previous bytes: %w", publishErr, rollbackSyncErr)
		}
		return publishErr
	}
	if err := os.Remove(rollbackTemp); err == nil {
		rollbackTemp = ""
	}
	return nil
}

func stageFile(dir, prefix string, data []byte, sourceInfo os.FileInfo) (string, error) {
	file, err := os.CreateTemp(dir, "."+prefix+".*.tmp")
	if err != nil {
		return "", fmt.Errorf("create staged config: %w", err)
	}
	path := file.Name()
	keep := false
	defer func() {
		if !keep {
			file.Close()
			os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return "", fmt.Errorf("write staged config: %w", err)
	}
	if err := preserveOwnership(file, sourceInfo); err != nil {
		return "", err
	}
	if err := file.Chmod(sourceInfo.Mode().Perm()); err != nil {
		return "", fmt.Errorf("preserve config mode: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("fsync staged config: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close staged config: %w", err)
	}
	keep = true
	return path, nil
}

func syncDirectory(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open config directory for fsync: %w", err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("fsync config directory: %w", err)
	}
	return nil
}
