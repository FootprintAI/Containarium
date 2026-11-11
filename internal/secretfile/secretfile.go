// Package secretfile writes secret material (private keys, tokens) to disk
// with mode 0600 regardless of any file already at the path.
package secretfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write atomically replaces path with data at mode 0600. os.WriteFile keeps
// the mode of a file that already exists, so a looser pre-existing file would
// stay readable; here the content goes to a 0600 temp file in the same
// directory, is fsynced, and is renamed over path.
func Write(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod temp for %s: %w", path, err)
	}
	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("write temp for %s: %w", path, err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("sync temp for %s: %w", path, err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close temp for %s: %w", path, err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename into %s: %w", path, err)
	}
	return nil
}
