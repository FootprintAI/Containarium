package runner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// flakyInstaller fails IsInstalled with a publickey-style handshake error
// for the first failN calls, then succeeds — modeling a freshly-created
// box that isn't reachable via the sentinel until the keysync propagates
// its authorized_keys into sshpiper. Install is a no-op (unused here).
type flakyInstaller struct {
	mu        sync.Mutex
	calls     int
	failN     int
	installed bool
}

func (f *flakyInstaller) IsInstalled(_ context.Context, _ string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failN {
		return false, fmt.Errorf("ssh handshake: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")
	}
	return f.installed, nil
}

func (f *flakyInstaller) Install(context.Context, string, []byte, map[string]string) error {
	return nil
}

// TestWaitForSSHInstalled_RetriesThroughKeysync is the #475 regression:
// the install-state probe must retry across the sshd-startup + sentinel-
// keysync window (transient publickey/dial failures on a fresh box) rather
// than failing the whole provision on the first miss.
func TestWaitForSSHInstalled_RetriesThroughKeysync(t *testing.T) {
	orig := sshProbeInitialBackoff
	sshProbeInitialBackoff = time.Millisecond
	t.Cleanup(func() { sshProbeInitialBackoff = orig })

	f := &flakyInstaller{failN: 3, installed: true}
	installed, err := waitForSSHInstalled(context.Background(), f, "box", 5*time.Second)
	if err != nil {
		t.Fatalf("waitForSSHInstalled returned error after %d probes, want success once SSH comes up: %v", f.calls, err)
	}
	if !installed {
		t.Errorf("installed = false, want true (IsInstalled result must pass through once SSH succeeds)")
	}
	if f.calls < 4 {
		t.Errorf("probe called %d times, want >=4 (3 transient failures + 1 success)", f.calls)
	}
}

// TestWaitForSSHInstalled_FailsAfterTimeout: a box that never becomes
// reachable still fails — bounded, with an actionable error.
func TestWaitForSSHInstalled_FailsAfterTimeout(t *testing.T) {
	orig := sshProbeInitialBackoff
	sshProbeInitialBackoff = time.Millisecond
	t.Cleanup(func() { sshProbeInitialBackoff = orig })

	f := &flakyInstaller{failN: 1 << 30} // never succeeds
	_, err := waitForSSHInstalled(context.Background(), f, "box", 40*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error after readyTimeout, got nil")
	}
	if !strings.Contains(err.Error(), "not reachable") {
		t.Errorf("error = %q, want it to mention the box was not reachable", err)
	}
}
