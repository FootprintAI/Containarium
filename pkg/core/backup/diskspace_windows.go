//go:build windows

package backup

import "errors"

// statDiskSpace is unsupported on Windows: the daemon, and so whole-box
// backup, runs on Linux only. The package still builds for the client.
func statDiskSpace(string) (diskSpace, error) {
	return diskSpace{}, errors.New("free-space pre-flight is not supported on windows")
}
