//go:build !linux

package server

import (
	"errors"

	"github.com/footprintai/containarium/internal/threatdetect"
)

// bootClockTicks: the exec watcher and the kill need Linux. Elsewhere there
// is no stamp, and a kill without one is refused (START_TIME_UNKNOWN).
func bootClockTicks() (threatdetect.ProcStartTicks, error) {
	return 0, errors.New("boot clock is read on Linux only")
}
