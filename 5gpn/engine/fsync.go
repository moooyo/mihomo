package engine

import (
	"fmt"
	"os"
	"runtime"
)

// syncDir fsyncs a directory so a rename into it is durable.
//
// It came from the bundle store, which is gone -- staging a bundle for another
// process to commit is not a thing that happens in one address space. This part
// was never about that. A script calling storage.set gets true back, and the
// write behind it is a temp file renamed into place; without the directory
// fsync the rename itself survives no power cut, so the entry can still name the
// old inode or a temp file that was subsequently removed. The script was told
// the write happened. That is the bug this prevents, and it outlived the
// two-process design that happened to house it.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("state: open %s: %w", dir, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("state: fsync %s: %w", dir, err)
	}
	return nil
}
