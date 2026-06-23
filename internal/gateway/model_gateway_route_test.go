package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/modelgateway"
)

// TestModelGatewayDiagnosticsRouting locks the embedded-daemon routing fix:
// the model-gateway handler is mounted under /v1/model/, but its #794
// /__gateway/status diagnostics gauge must ALSO be reachable at the daemon
// root — otherwise it falls through to the wake catch-all (the bug this fix
// addresses), and /v1/model/__gateway/status is parsed as a provider name.
//
// /__gateway/usage must NOT be exposed at root: it carries per-tenant token
// counts and the handler is unwrapped by JWT auth.
//
// The test mirrors the relevant routes registered in GatewayServer.Start()
// (the real mux is built there, intertwined with listener setup, so it isn't
// unit-constructable) against the REAL model-gateway handler.
func TestModelGatewayDiagnosticsRouting(t *testing.T) {
	gw := modelgateway.New(modelgateway.Config{}).Handler()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		// Stand-in for the daemon's wake catch-all.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("wake: no matching route"))
	})
	mux.Handle("/v1/model/", gw)
	// The two lines under test (must match gateway.go Start()).
	mux.Handle("/__gateway/status", gw)
	mux.Handle("/__gateway/healthz", gw)

	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code, rec.Body.String()
	}

	// /__gateway/status is reachable at root and returns the inflight gauge.
	code, body := get("/__gateway/status")
	if code != http.StatusOK {
		t.Fatalf("/__gateway/status: want 200, got %d (%s)", code, body)
	}
	var gauge map[string]any
	if err := json.Unmarshal([]byte(body), &gauge); err != nil {
		t.Fatalf("/__gateway/status body not JSON: %v (%s)", err, body)
	}
	if _, ok := gauge["inflight"]; !ok {
		t.Errorf("/__gateway/status missing inflight gauge: %s", body)
	}

	// /__gateway/healthz is reachable at root.
	if code, _ := get("/__gateway/healthz"); code != http.StatusOK {
		t.Errorf("/__gateway/healthz: want 200, got %d", code)
	}

	// /__gateway/usage is NOT exposed at root → falls to the wake catch-all.
	if _, body := get("/__gateway/usage"); !strings.Contains(body, "wake: no matching route") {
		t.Errorf("/__gateway/usage must not be exposed at daemon root; got %q", body)
	}
}
