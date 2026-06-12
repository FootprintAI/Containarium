package mcp

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/transfer"
)

// TestSentinelHint_RewritesUnresolvedError verifies that an unresolved-sentinel
// failure from transfer is turned into agent-native guidance: point at
// get_container / the connect tool, and explicitly say the env var is NOT
// required. This is the fix for agents that chased CONTAINARIUM_SENTINEL_HOST
// and gave up (issue #658).
func TestSentinelHint_RewritesUnresolvedError(t *testing.T) {
	err := sentinelHint("push", "alice", fmt.Errorf("%w: boom", transfer.ErrSentinelUnresolved))
	msg := err.Error()

	for _, want := range []string{"get_container", "ssh_host", "connect", "alice"} {
		if !strings.Contains(msg, want) {
			t.Errorf("guidance missing %q; got: %s", want, msg)
		}
	}
	if !strings.Contains(msg, "do not need to set CONTAINARIUM_SENTINEL_HOST") {
		t.Errorf("guidance should steer away from the env var; got: %s", msg)
	}
	// The typed cause must remain unwrappable for callers up the stack.
	if !errors.Is(err, transfer.ErrSentinelUnresolved) {
		t.Errorf("wrapped error must stay matchable with errors.Is")
	}
}

// TestSentinelHint_PassesThroughOtherErrors verifies non-sentinel failures
// are not rewritten with sentinel guidance (which would be misleading).
func TestSentinelHint_PassesThroughOtherErrors(t *testing.T) {
	err := sentinelHint("sync", "bob", fmt.Errorf("ssh key not readable"))
	msg := err.Error()
	if strings.Contains(msg, "ssh_host") || strings.Contains(msg, "get_container") {
		t.Errorf("non-sentinel error should not get sentinel guidance; got: %s", msg)
	}
	if !strings.Contains(msg, "sync failed") || !strings.Contains(msg, "ssh key not readable") {
		t.Errorf("non-sentinel error should be wrapped plainly; got: %s", msg)
	}
}
