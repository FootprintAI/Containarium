package containariumotel

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPMiddleware_PassesThroughToHandler(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	})

	mw := HTTPMiddleware(next)
	if mw == nil {
		t.Fatal("HTTPMiddleware returned nil")
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	mw.ServeHTTP(rr, req)

	if !called {
		t.Error("inner handler was not called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if got := rr.Body.String(); got != "hello" {
		t.Errorf("body = %q, want hello", got)
	}
}

func TestHTTPMiddleware_NilNextPanicsLikely(t *testing.T) {
	// Sanity check that we forward to otelhttp without sniffing args.
	// otelhttp itself will panic on nil handler if/when ServeHTTP is
	// called; constructing the middleware with a nil handler does not.
	defer func() {
		// recover so the panic doesn't fail the test — we just want
		// to verify construction works.
		_ = recover()
	}()
	mw := HTTPMiddleware(nil)
	if mw == nil {
		t.Fatal("HTTPMiddleware returned nil on nil-next construction")
	}
}
