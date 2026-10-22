//go:build !linux

package server

import "errors"

// openPID: the daemon's kill path needs Linux (cgroup v2, pidfd). Elsewhere
// it refuses, so a dev build compiles but never signals anything.
func openPID(int) (pidHandle, error) {
	return nil, errors.New("process kill is supported on Linux only")
}
