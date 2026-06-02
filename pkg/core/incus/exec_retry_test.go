package incus

import (
	"errors"
	"fmt"
	"testing"
)

// noBackoff zeroes execBackoffBase for the duration of a test so the
// retry loop doesn't actually sleep.
func noBackoff(t *testing.T) {
	t.Helper()
	old := execBackoffBase
	execBackoffBase = 0
	t.Cleanup(func() { execBackoffBase = old })
}

// transientErr mimics the incus exec PID-tracking failure as it surfaces
// from the wrapper (wrapped in "command execution failed: …").
var transientErr = fmt.Errorf("command execution failed: %w",
	errors.New("Failed to retrieve PID of executing child process"))

func TestIsTransientExecErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"transient PID race", transientErr, true},
		{"wrapped transient", fmt.Errorf("exec foo: %w", transientErr), true},
		{"real non-zero exit", errors.New("command exited with code 1"), false},
		{"other failure", errors.New("instance not found"), false},
	}
	for _, c := range cases {
		if got := isTransientExecErr(c.err); got != c.want {
			t.Errorf("%s: isTransientExecErr = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestExecWithRetry_RetriesTransientThenSucceeds: the transient PID error
// is retried and a later success is returned cleanly.
func TestExecWithRetry_RetriesTransientThenSucceeds(t *testing.T) {
	noBackoff(t)
	calls := 0
	err := execWithRetry("test", func() error {
		calls++
		if calls < 3 {
			return transientErr
		}
		return nil
	})
	if err != nil {
		t.Fatalf("err = %v, want nil after transient retries", err)
	}
	if calls != 3 {
		t.Errorf("attempts = %d, want 3 (2 transient + 1 success)", calls)
	}
}

// TestExecWithRetry_DoesNotRetryRealError: a genuine command failure
// (non-transient) must NOT be retried — retrying could double-run a
// non-idempotent side effect.
func TestExecWithRetry_DoesNotRetryRealError(t *testing.T) {
	noBackoff(t)
	calls := 0
	realErr := errors.New("command exited with code 1")
	err := execWithRetry("test", func() error {
		calls++
		return realErr
	})
	if !errors.Is(err, realErr) {
		t.Fatalf("err = %v, want the real error", err)
	}
	if calls != 1 {
		t.Errorf("attempts = %d, want 1 (no retry on a real failure)", calls)
	}
}

// TestExecWithRetry_ExhaustsAndReturnsLast: a persistently transient error
// is retried up to the cap, then the last error is returned.
func TestExecWithRetry_ExhaustsAndReturnsLast(t *testing.T) {
	noBackoff(t)
	calls := 0
	err := execWithRetry("test", func() error {
		calls++
		return transientErr
	})
	if !isTransientExecErr(err) {
		t.Fatalf("err = %v, want the transient error after exhaustion", err)
	}
	if calls != execMaxAttempts {
		t.Errorf("attempts = %d, want execMaxAttempts (%d)", calls, execMaxAttempts)
	}
}
