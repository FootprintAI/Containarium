package github

import (
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
)

// #2045: the default HTTP client must not time out before the detached
// upstream create budget — otherwise the client's own timeout always wins
// and tracker.UpstreamCreateTimeout never takes effect.
func TestNew_DefaultHTTPTimeoutCoversTheUpstreamCreateBudget(t *testing.T) {
	got := New(nil).http.Timeout
	if got < tracker.UpstreamCreateTimeout {
		t.Fatalf("default HTTP client timeout = %v, shorter than tracker.UpstreamCreateTimeout = %v", got, tracker.UpstreamCreateTimeout)
	}
}
