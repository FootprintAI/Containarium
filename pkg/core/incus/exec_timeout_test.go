package incus

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// waitWithTimeout bounds an Operation.WaitContext-shaped call (cloud#1128):
// op.Wait() has no deadline of its own, so a wedged Incus operation — same
// class of liblxc-socket flakiness this file already retries around for
// GetInstanceState (isTransientStateErr, citing OSS #931) — blocks its
// caller forever instead of surfacing an error. The Incus SDK's
// Operation.WaitContext performs a genuine `select` on ctx.Done() (verified
// against github.com/lxc/incus/v7/client), so a deadline-bound context
// actually interrupts a wedged wait; wait below simulates exactly that
// select by blocking on ctx.Done() itself, mirroring what the real SDK does
// when the underlying operation never completes.

func TestWaitWithTimeout_WedgedOperationTimesOutRatherThanHangingForever(t *testing.T) {
	wedged := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}

	start := time.Now()
	err := waitWithTimeout(20*time.Millisecond, wedged)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("waitWithTimeout blocked for %s — not bounded by the timeout", elapsed)
	}
	if err == nil {
		t.Fatal("wedged operation must return an error, not nil")
	}
	if !strings.Contains(err.Error(), "wedged") {
		t.Errorf("error should say the operation looks wedged, not just cancelled: %q", err.Error())
	}
}

func TestWaitWithTimeout_SuccessPassesThrough(t *testing.T) {
	ok := func(ctx context.Context) error { return nil }
	if err := waitWithTimeout(time.Second, ok); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

// A genuine command failure (the operation completed, just with an error)
// must be distinguishable from a timeout — a caller retrying on "wedged"
// should not retry a real, already-finished failure the same way.
func TestWaitWithTimeout_RealErrorIsNotReportedAsATimeout(t *testing.T) {
	realErr := errors.New("command exited with code 1")
	fails := func(ctx context.Context) error { return realErr }

	err := waitWithTimeout(time.Second, fails)
	if err == nil || !errors.Is(err, realErr) {
		t.Fatalf("want the real error wrapped, got %v", err)
	}
	if strings.Contains(err.Error(), "wedged") {
		t.Errorf("a real command failure must not be described as wedged: %q", err.Error())
	}
}

// The context passed to wait must actually carry the requested deadline —
// otherwise waitWithTimeout could time out on its own goroutine bookkeeping
// while still handing wait an unbounded context.
func TestWaitWithTimeout_PassesADeadlineBoundContext(t *testing.T) {
	var sawDeadline bool
	check := func(ctx context.Context) error {
		_, sawDeadline = ctx.Deadline()
		return nil
	}
	if err := waitWithTimeout(time.Second, check); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sawDeadline {
		t.Error("wait was called with a context that has no deadline")
	}
}
