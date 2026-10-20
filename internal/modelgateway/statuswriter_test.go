package modelgateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// unwrapOnly is a wrapper that offers no Flusher of its own: the embedded
// field is the http.ResponseWriter interface, so the recorder's Flush is not
// promoted, and the only way down to it is Unwrap.
type unwrapOnly struct{ http.ResponseWriter }

func (u unwrapOnly) Unwrap() http.ResponseWriter { return u.ResponseWriter }

// #2773 review: statusWriter used to carry its own Flush(), a bare
// s.ResponseWriter.(http.Flusher) assertion that no-ops on failure. The
// controller prefers Flusher over Unwrap, so with another wrapper underneath
// the flush silently went nowhere. Now the flush must travel statusWriter →
// Unwrap → unwrapOnly → Unwrap → recorder.
func TestStatusWriter_FlushReachesRecorderThroughNestedUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: unwrapOnly{rec}, status: http.StatusOK}

	if err := http.NewResponseController(sw).Flush(); err != nil {
		t.Fatalf("Flush through nested wrappers: %v", err)
	}
	if !rec.Flushed {
		t.Fatal("flush did not reach the bottom recorder")
	}
}

// The END log reads the first status the proxy wrote; a later WriteHeader
// (which net/http would reject anyway) must not overwrite it.
func TestStatusWriter_CapturesFirstStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, status: http.StatusOK}
	sw.WriteHeader(http.StatusBadGateway)
	sw.WriteHeader(http.StatusOK)
	if sw.status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", sw.status)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("recorder code = %d, want 502", rec.Code)
	}
}
