package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// #2773: the wrapper (httpx.StatusWriter, tested there) must let
// http.NewResponseController reach the real Flusher; this proves it through
// the metrics middleware itself.
func TestHTTPMetricsMiddleware_StreamingHandlerCanFlush(t *testing.T) {
	mp := sdkmetric.NewMeterProvider()
	// context.Background(): t.Context() is already cancelled inside Cleanup,
	// which would make Shutdown return before it has done anything.
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
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
	if !rec.Flushed {
		t.Fatal("underlying writer was not flushed")
	}
}
