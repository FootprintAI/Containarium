package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// #2773: streaming responses flush after every chunk through
// http.NewResponseController; the status-capturing wrapper (now
// httpx.StatusWriter, tested there) must let that reach the real writer.
// This proves it through the audit middleware itself, on an audited path.
func TestHTTPAuditMiddleware_StreamingHandlerCanFlush(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		for i := 0; i < 3; i++ {
			_, _ = w.Write([]byte("chunk\n"))
			if err := rc.Flush(); err != nil {
				t.Errorf("flush %d: %v", i, err)
				return
			}
		}
	})
	rec := httptest.NewRecorder()
	HTTPAuditMiddleware(inner, errAuditLogger{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/security/exec-events", nil))
	if rec.Body.String() != "chunk\nchunk\nchunk\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if !rec.Flushed {
		t.Fatal("underlying writer was not flushed")
	}
}

// The audit row records the status the handler wrote through the shared
// wrapper (status capture moved to httpx.StatusWriter with #2773).
func TestHTTPAuditMiddleware_CapturesHandlerStatus(t *testing.T) {
	logger := &fakeAuditLogger{}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	rec := httptest.NewRecorder()
	HTTPAuditMiddleware(inner, logger).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/security/exec-events", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("response status = %d, want 418", rec.Code)
	}
	deadline := time.Now().Add(2 * time.Second)
	for logger.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	entry := logger.first()
	if entry == nil {
		t.Fatal("audit entry never written")
	}
	if entry.StatusCode != http.StatusTeapot {
		t.Fatalf("audit status = %d, want 418", entry.StatusCode)
	}
}
