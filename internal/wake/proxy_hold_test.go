package wake

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// A wake for a held box is refused with 503 and a short body, is logged with
// the box name, and does not invite a retry (#3721).
func TestWakeProxy_HeldBoxIsRefusedAndLogged(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	const fullDomain = "alice-web.example.test"
	proxy := NewWakeProxy(
		&fakeStarter{err: fmt.Errorf("start: %w", ErrBoxHeld)},
		&fakeLookup{fullDomain: fullDomain, containerName: "alice-container", targetIP: "127.0.0.1", targetPort: 1},
		&fakeRouteStore{},
		nil,
		nil,
		time.Second,
	)

	req := httptest.NewRequest(http.MethodGet, "http://"+fullDomain+"/", nil)
	req.Host = fullDomain
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%q", rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "wake: box is held" {
		t.Errorf("body = %q, want %q", got, "wake: box is held")
	}
	if ra := rec.Header().Get("Retry-After"); ra != "" {
		t.Errorf("Retry-After = %q; a held box must not invite a retry", ra)
	}
	if !strings.Contains(logs.String(), `[wake] refused: box="alice" is held by the operator`) {
		t.Errorf("log does not record the refused wake with the box name:\n%s", logs.String())
	}
}
