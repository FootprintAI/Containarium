package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// #2773: the wrapper must let http.NewResponseController reach the real
// Flusher, otherwise server-streaming responses break.
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

func TestHTTPMetricsMiddleware_StreamingHandlerCanFlush(t *testing.T) {
	mp := sdkmetric.NewMeterProvider()
	t.Cleanup(func() { _ = mp.Shutdown(t.Context()) })
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
	HTTPMetricsMiddleware(inner, mp).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/x", nil))
	if rec.Body.String() != "chunk\nchunk\nchunk\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}
