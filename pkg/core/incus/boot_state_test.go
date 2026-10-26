package incus_test

import (
	"strings"
	"testing"
)

// bootState classifies one `systemctl is-system-running` answer for the
// lane's waitForBoot (#2801). It runs in the default unit lane, so the
// parsing is proven without an Incus host.
func TestBootState(t *testing.T) {
	for _, tc := range []struct {
		stdout string
		want   bootPhase
	}{
		{"running\n", bootDone},
		{"degraded\n", bootDone}, // exits 1, and is a finished boot
		{"  running  ", bootDone},
		{"starting\n", bootPending},
		{"initializing\n", bootPending},
		{"", bootPending}, // no systemd bus yet, or the exec agent not ready: retry
		{"\n", bootPending},
		{"offline\n", bootPending}, // the manager is not up yet
		{"unknown\n", bootPending},
		{"maintenance\n", bootFailed},
		{"stopping\n", bootFailed},
		{"running\nextra\n", bootDone}, // first line is the state
	} {
		if got := bootState(tc.stdout); got != tc.want {
			t.Errorf("bootState(%q) = %v, want %v", strings.TrimSpace(tc.stdout), got, tc.want)
		}
	}
}

// bootPhase is what one `systemctl is-system-running` answer means for a
// test waiting on a box's boot.
type bootPhase int

const (
	bootPending bootPhase = iota // still booting, or no answer yet: ask again
	bootDone                     // running or degraded: the boot jobs have finished
	bootFailed                   // a state a booting box does not pass through
)

func (p bootPhase) String() string {
	return [...]string{"pending", "done", "failed"}[p]
}

// bootState reads the first line of `systemctl is-system-running`. The exit
// code is not used: the command exits 1 for "degraded", which a container
// often is, and for every state before "running".
func bootState(stdout string) bootPhase {
	state, _, _ := strings.Cut(strings.TrimSpace(stdout), "\n")
	switch strings.TrimSpace(state) {
	case "running", "degraded":
		return bootDone
	case "maintenance", "stopping":
		return bootFailed
	default:
		// "", "initializing", "starting", "offline", "unknown": systemd
		// is not up yet, or the exec reached the box before its init did.
		return bootPending
	}
}
