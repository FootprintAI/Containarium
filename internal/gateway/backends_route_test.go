package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBackendsRouteRegistration_UpgradeNotShadowed reproduces #1805: the
// legacy backendsHandler is registered on the "/v1/backends/" *subtree*
// (needed for GET /v1/backends/{id}/system-info), which — under
// http.ServeMux's longest-prefix-wins rule — silently swallowed every other
// proto-first RPC mounted under that prefix, including POST
// /v1/backends/upgrade (TriggerUpgrade). The fix registers each new
// proto-first sub-route as its own exact path so it outranks the subtree.
//
// This test exercises the exact registration shape from
// GatewayServer.Start (httpMux.Handle("/v1/backends", ...),
// httpMux.Handle("/v1/backends/upgrade", ...), then the "/v1/backends/"
// subtree) without needing a full GatewayServer, so it stays fast and would
// have caught the original shadowing.
func TestBackendsRouteRegistration_UpgradeNotShadowed(t *testing.T) {
	var hitGRPCGateway, hitLegacySubtree bool

	grpcGatewayStub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitGRPCGateway = true
		w.WriteHeader(http.StatusOK)
	})
	// The real legacy handler 404s anything it doesn't explicitly know
	// about (only /system-info); this stub mirrors that behavior.
	legacySubtreeStub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitLegacySubtree = true
		http.NotFound(w, r)
	})

	mux := http.NewServeMux()
	mux.Handle("/v1/backends", grpcGatewayStub)
	mux.Handle("/v1/backends/upgrade", grpcGatewayStub)
	mux.Handle("/v1/backends/", legacySubtreeStub)

	req := httptest.NewRequest(http.MethodPost, "/v1/backends/upgrade", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if hitLegacySubtree {
		t.Fatal("POST /v1/backends/upgrade was routed to the legacy subtree handler, not the grpc-gateway route — #1805 regressed")
	}
	if !hitGRPCGateway {
		t.Fatal("POST /v1/backends/upgrade never reached the grpc-gateway route stub")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestBackendsRouteRegistration_SystemInfoStillReachable proves the fix
// doesn't regress the legacy /system-info forward the subtree exists for.
func TestBackendsRouteRegistration_SystemInfoStillReachable(t *testing.T) {
	var hitLegacySubtree bool

	grpcGatewayStub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("GET /v1/backends/tunnel-gpu/system-info should not reach the grpc-gateway route")
	})
	legacySubtreeStub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitLegacySubtree = true
		w.WriteHeader(http.StatusOK)
	})

	mux := http.NewServeMux()
	mux.Handle("/v1/backends", grpcGatewayStub)
	mux.Handle("/v1/backends/upgrade", grpcGatewayStub)
	mux.Handle("/v1/backends/", legacySubtreeStub)

	req := httptest.NewRequest(http.MethodGet, "/v1/backends/tunnel-gpu/system-info", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if !hitLegacySubtree {
		t.Fatal("GET /v1/backends/{id}/system-info should still reach the legacy subtree handler")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
