package client

import (
	"testing"

	"github.com/footprintai/containarium/internal/server"
)

// #3581: the capability the client gates run_token on is the one the daemon
// advertises. The two constants live in packages that cannot share one (the
// daemon does not import the client), so a rename on either side fails here
// instead of leaving every token refused, or every token sent to a daemon
// that ignores it.
func TestBoxRunTokenCapability_IsTheDaemons(t *testing.T) {
	if BoxRunTokenCapability != server.DaemonCapBoxRunToken {
		t.Fatalf("client gates on %q, the daemon advertises %q", BoxRunTokenCapability, server.DaemonCapBoxRunToken)
	}
}
