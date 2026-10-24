package security

import (
	"errors"
	"os/exec"
	"testing"
)

// shExit runs script with the host's /bin/sh and returns its exit status.
func shExit(t *testing.T, script string) int {
	t.Helper()
	err := exec.Command("sh", "-c", script).Run()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	t.Fatalf("sh could not run: %v", err)
	return -1
}

// Incus reports an exec exit status of 127 as an error, so a presence probe
// must exit 0 or 1 and never 127, whatever /bin/sh is (dash returns 127 for
// `command -v <missing>`; bash returns 1).
func TestPresenceProbeExitsOneWhenMissing(t *testing.T) {
	if got := shExit(t, presenceProbe("definitely-not-an-installed-binary-xyz")); got != 1 {
		t.Fatalf("missing binary: exit %d, want 1", got)
	}
	if got := shExit(t, presenceProbe("sh")); got != 0 {
		t.Fatalf("present binary: exit %d, want 0", got)
	}
}

func TestInstallAndScanProbesNeverExit127(t *testing.T) {
	for name, script := range map[string]string{
		"clamscan": presenceProbe("clamscan"),
		"debian":   debianFamilyProbe,
	} {
		if got := shExit(t, script); got != 0 && got != 1 {
			t.Errorf("%s probe exited %d, want 0 or 1", name, got)
		}
	}
}
