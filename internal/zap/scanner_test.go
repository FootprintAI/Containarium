package zap

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestEnsureDaemonRunning_FailsFastWhenNotInstalled locks down the fix for
// #960: EnsureDaemonRunning must check Scanner.Available() (which delegates
// to Installer.IsInstalled(), an `incus exec ... test -x .../zap.sh` shell
// call) before attempting to start the daemon, and return immediately with
// a clear error instead of backgrounding a doomed start command and burning
// the full 120-second readiness poll.
//
// No incus daemon or security container exists in the CI/test environment,
// so IsInstalled() naturally reports "not installed" here (the underlying
// `incus` binary is either absent or the container doesn't exist) — this
// exercises the real code path end to end rather than mocking it.
func TestEnsureDaemonRunning_FailsFastWhenNotInstalled(t *testing.T) {
	s := NewScanner()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err := s.EnsureDaemonRunning(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when ZAP is not installed, got nil")
	}
	if !strings.Contains(err.Error(), "not installed") {
		t.Errorf("expected a clear 'not installed' error, got: %v", err)
	}
	// The old behavior polled for up to 120 seconds before giving up. The
	// fail-fast check must short-circuit well before that — give it a
	// generous ceiling (well under the old 120s timeout) so this test
	// isn't flaky on a slow CI box, while still catching a regression back
	// to the old poll-for-120-seconds behavior.
	if elapsed >= 10*time.Second {
		t.Errorf("EnsureDaemonRunning took %s — expected a fast failure, not a slow poll", elapsed)
	}
}

// TestScanner_Available mirrors the same not-installed path via the public
// Available() accessor, which EnsureDaemonRunning calls first.
func TestScanner_Available(t *testing.T) {
	s := NewScanner()
	if s.Available() {
		t.Skip("ZAP appears to be installed in this environment; not-installed path can't be exercised here")
	}
}
