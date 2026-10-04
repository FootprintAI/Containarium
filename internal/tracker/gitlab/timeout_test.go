package gitlab

import (
	"net/http"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/tracker"
)

// #2045: a create runs under the upstream create budget, every other call
// under the general default, and a caller-supplied client is used as given
// for both.
func TestNew_CreateUsesUpstreamCreateBudget(t *testing.T) {
	a := New(nil)
	if got := a.http.Timeout; got != tracker.DefaultHTTPTimeout {
		t.Fatalf("default client timeout = %v, want %v", got, tracker.DefaultHTTPTimeout)
	}
	if got := a.create.Timeout; got != tracker.UpstreamCreateTimeout {
		t.Fatalf("create client timeout = %v, want %v", got, tracker.UpstreamCreateTimeout)
	}
}

func TestNew_CallerClientUsedForCreatesToo(t *testing.T) {
	a := New(&http.Client{Timeout: 200 * time.Millisecond})
	if a.create.Timeout != 200*time.Millisecond || a.http.Timeout != 200*time.Millisecond {
		t.Fatalf("caller timeout not kept: http=%v create=%v", a.http.Timeout, a.create.Timeout)
	}
}
