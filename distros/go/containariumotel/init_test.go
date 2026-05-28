package containariumotel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newOTLPSink returns an httptest.Server that accepts OTLP/HTTP POSTs
// with a 200 OK. Used in tests where we want Init to succeed without
// pointing at the actual collector. Cleaned up via t.Cleanup.
func newOTLPSink(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestInit_FailOpenWithoutEndpoint(t *testing.T) {
	_resetForTests()
	clearEnv(t)
	shutdown, err := Init(context.Background())
	if err != nil {
		t.Fatalf("Init returned error in fail-open path: %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown was nil; expected noopShutdown")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("no-op shutdown returned error: %v", err)
	}
}

func TestInit_WithEndpoint(t *testing.T) {
	_resetForTests()
	clearEnv(t)
	srv := newOTLPSink(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("OTEL_SERVICE_NAME", "test-svc")
	t.Setenv("CONTAINARIUM_CONTAINER_ID", "alice-container")
	t.Setenv("CONTAINARIUM_BACKEND_ID", "node-7")
	t.Setenv("CONTAINARIUM_TENANT_ID", "alice")

	shutdown, err := Init(context.Background())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown nil")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

func TestInit_Idempotent(t *testing.T) {
	_resetForTests()
	clearEnv(t)
	srv := newOTLPSink(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)

	shutdown1, _ := Init(context.Background())
	shutdown2, _ := Init(context.Background())
	// We can't compare func values directly in Go; the contract is
	// that the sync.Once gate means the second call's body didn't
	// run. Calling both shutdowns must not double-shut-down — the
	// shutdownOnce inside makes that safe regardless.
	_ = shutdown1(context.Background())
	_ = shutdown2(context.Background())
}

func TestWithServiceName_RespectsExistingEnv(t *testing.T) {
	// Re-tests the setdefault-style behavior: explicit env wins.
	_resetForTests()
	clearEnv(t)
	srv := newOTLPSink(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("OTEL_SERVICE_NAME", "from-env")

	_, err := Init(context.Background(), WithServiceName("from-opt"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	cfg := ConfigFromEnv()
	if cfg.ServiceName != "from-env" {
		t.Errorf("ServiceName = %q, want from-env (env should win over option)", cfg.ServiceName)
	}
}

func TestWithServiceName_FillsWhenEnvUnset(t *testing.T) {
	_resetForTests()
	clearEnv(t)
	srv := newOTLPSink(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	// OTEL_SERVICE_NAME deliberately unset.

	_, err := Init(context.Background(), WithServiceName("from-opt"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	cfg := ConfigFromEnv()
	if cfg.ServiceName != "from-opt" {
		t.Errorf("ServiceName = %q, want from-opt (option should fill missing env)", cfg.ServiceName)
	}
}
