package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// #2773: streaming responses flush after every chunk through
// http.NewResponseController, which needs Unwrap on the wrapper.
func TestResponseWriter_FlushesThroughUnwrapAndCapturesStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := newResponseWriter(rec)

	rw.WriteHeader(http.StatusTeapot)
	if rw.statusCode != http.StatusTeapot || rec.Code != http.StatusTeapot {
		t.Fatalf("status capture = %d / %d, want 418", rw.statusCode, rec.Code)
	}
	if err := http.NewResponseController(rw).Flush(); err != nil {
		t.Fatalf("Flush through wrapper: %v", err)
	}
	if !rec.Flushed {
		t.Fatal("underlying writer was not flushed")
	}
	if rw.Unwrap() != http.ResponseWriter(rec) {
		t.Fatal("Unwrap did not return the underlying writer")
	}
}

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
}
