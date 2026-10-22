package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// #2773: streaming responses flush after every chunk through
// http.NewResponseController, which needs Unwrap on the wrapper.
func TestStatusWriter_FlushesThroughUnwrapAndCapturesStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := NewStatusWriter(rec)

	if sw.StatusCode != http.StatusOK {
		t.Fatalf("initial status = %d, want 200", sw.StatusCode)
	}
	sw.WriteHeader(http.StatusTeapot)
	if sw.StatusCode != http.StatusTeapot || rec.Code != http.StatusTeapot {
		t.Fatalf("status capture = %d / %d, want 418", sw.StatusCode, rec.Code)
	}
	if err := http.NewResponseController(sw).Flush(); err != nil {
		t.Fatalf("Flush through wrapper: %v", err)
	}
	if !rec.Flushed {
		t.Fatal("underlying writer was not flushed")
	}
	if sw.Unwrap() != http.ResponseWriter(rec) {
		t.Fatal("Unwrap did not return the underlying writer")
	}
}

// A StatusWriter around a writer that offers no Flusher still reports
// http.ErrNotSupported rather than silently succeeding.
func TestStatusWriter_FlushWithoutFlusherIsNotSupported(t *testing.T) {
	sw := NewStatusWriter(struct{ http.ResponseWriter }{httptest.NewRecorder()})
	// The controller wraps the sentinel, so errors.Is, not ==.
	if err := http.NewResponseController(sw).Flush(); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("Flush = %v, want http.ErrNotSupported", err)
	}
}
