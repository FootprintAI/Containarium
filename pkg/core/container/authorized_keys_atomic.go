package container

import (
	"fmt"
	"os"
)

// authorizedKeysChown sets the owner of the temp file that becomes
// authorized_keys. It acts on the open file, so the change lands on the inode
// that is renamed into place. A var so tests can make it fail.
var authorizedKeysChown = func(f *os.File, uid, gid int) error {
	return f.Chown(uid, gid)
}

// writeAuthorizedKeysAt atomically replaces authorized_keys under dirFd with
// data. The temp file is created under dirFd, so no path component is followed.
// It is owned by uid:gid before the rename, and a failed chown aborts before the
// live file is touched.
func writeAuthorizedKeysAt(dirFd int, data []byte, uid, gid int) error {
	tmp, tmpName, err := createTempFileAt(dirFd, ".authorized_keys.tmp.")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer func() { _ = removeFileAt(dirFd, tmpName) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync tmp: %w", err)
	}
	if err := authorizedKeysChown(tmp, uid, gid); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := renameFileAt(dirFd, tmpName, "authorized_keys"); err != nil {
		return fmt.Errorf("rename tmp -> authorized_keys: %w", err)
	}
	return syncDirFD(dirFd)
}
