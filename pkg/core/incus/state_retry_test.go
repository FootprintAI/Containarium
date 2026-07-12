package incus

import (
	"errors"
	"fmt"
	"testing"

	"github.com/lxc/incus/v6/shared/api"
)

// noStateBackoff zeroes stateBackoffBase for the duration of a test so the
// retry loop doesn't actually sleep.
func noStateBackoff(t *testing.T) {
	t.Helper()
	old := stateBackoffBase
	stateBackoffBase = 0
	t.Cleanup(func() { stateBackoffBase = old })
}

// errTransientState mimics the real error text GetInstanceState surfaces
// for a wedged-connection ghost instance (OSS #931) — verbatim, so the
// substring match in isTransientStateErr is exercised.
var errTransientState = errors.New(`Failed to fetch instance "cld-example-container" in project "default": Instance not found`) //nolint:staticcheck // ST1005: mirrors verbatim incus error text

func TestIsTransientStateErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"transient ghost instance", errTransientState, true},
		{"wrapped transient", fmt.Errorf("failed to get container state: %w", errTransientState), true},
		{"other failure", errors.New("connection refused"), false},
	}
	for _, c := range cases {
		if got := isTransientStateErr(c.err); got != c.want {
			t.Errorf("%s: isTransientStateErr = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestStateWithRetry_RetriesTransientThenSucceeds: the transient
// "Instance not found" error is retried and a later success is returned
// cleanly — reproducing the exact live behavior observed on OSS #931 (the
// same call succeeding on a subsequent attempt with nothing else changed).
func TestStateWithRetry_RetriesTransientThenSucceeds(t *testing.T) {
	noStateBackoff(t)
	calls := 0
	want := &api.InstanceState{Status: "Running"}
	state, _, err := stateWithRetry("test", func() (*api.InstanceState, string, error) {
		calls++
		if calls < 3 {
			return nil, "", errTransientState
		}
		return want, "etag", nil
	})
	if err != nil {
		t.Fatalf("err = %v, want nil after transient retries", err)
	}
	if state != want {
		t.Errorf("state = %v, want %v", state, want)
	}
	if calls != 3 {
		t.Errorf("attempts = %d, want 3 (2 transient + 1 success)", calls)
	}
}

// TestStateWithRetry_DoesNotRetryRealError: a genuine (non-transient)
// failure must return immediately, on the first attempt.
func TestStateWithRetry_DoesNotRetryRealError(t *testing.T) {
	noStateBackoff(t)
	calls := 0
	realErr := errors.New("connection refused")
	_, _, err := stateWithRetry("test", func() (*api.InstanceState, string, error) {
		calls++
		return nil, "", realErr
	})
	if !errors.Is(err, realErr) {
		t.Fatalf("err = %v, want the real error", err)
	}
	if calls != 1 {
		t.Errorf("attempts = %d, want 1 (no retry on a real failure)", calls)
	}
}

// TestStateWithRetry_ExhaustsAndReturnsLast: a persistently transient error
// (a genuinely deleted instance) is retried up to the cap, then the same
// error is returned — this must NEVER be silently swallowed into a fake
// success.
func TestStateWithRetry_ExhaustsAndReturnsLast(t *testing.T) {
	noStateBackoff(t)
	calls := 0
	_, _, err := stateWithRetry("test", func() (*api.InstanceState, string, error) {
		calls++
		return nil, "", errTransientState
	})
	if !isTransientStateErr(err) {
		t.Fatalf("err = %v, want the transient error after exhaustion", err)
	}
	if calls != stateMaxAttempts {
		t.Errorf("attempts = %d, want stateMaxAttempts (%d)", calls, stateMaxAttempts)
	}
}
