package sentinel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
)

const tunnelTokenAdminSecret = "zyxwvutsrqponmlkjihgfedcba9876543210ZYXW" // 40 bytes

func newManagerForTunnelTokenTest(t *testing.T, withPolicy bool) *Manager {
	t.Helper()
	m := &Manager{backends: NewBackendPool()}
	m.SetAdminSecret([]byte(tunnelTokenAdminSecret))
	if withPolicy {
		m.SetTunnelPolicy(NewTokenPolicy())
	}
	// Persist to a tmp dir, not the real /etc/containarium (#936) — a
	// hermetic test must not depend on (or fail attempting) a real
	// filesystem write to a root-owned path.
	m.SetTunnelTokenStorePath(t.TempDir() + "/tunnel-tokens.json")
	return m
}

func TestTunnelTokenRegisterHandler_RegistersFreshToken(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)

	// Before registration, the token is unknown — this is the exact
	// "invalid token" rejection reported in #799.
	if err := m.tunnelPolicy.Validate("fresh-token", ""); err == nil {
		t.Fatal("expected fresh token to be rejected before registration")
	}

	body, _ := json.Marshal(TunnelTokenRegisterRequest{Token: "fresh-token"})
	req := httptest.NewRequest(http.MethodPost, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenRegisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// No pools specified => PoolAny, so it matches any pool including
	// the empty one BYOC's `pool join` (no --pool flag) actually uses.
	if err := m.tunnelPolicy.Validate("fresh-token", ""); err != nil {
		t.Fatalf("token still rejected after registration: %v", err)
	}
	if err := m.tunnelPolicy.Validate("fresh-token", "asia-east1"); err != nil {
		t.Fatalf("token should match any pool (PoolAny default): %v", err)
	}
}

// TestTunnelTokenRegisterHandler_PersistsAcrossRestart is the regression
// guard for #936: a token registered at runtime must survive the sentinel
// process restarting, not just be valid in the current process's
// in-memory TokenPolicy. Simulates a restart by building a FRESH policy +
// loading the persisted store into it, mirroring exactly what
// internal/cmd/sentinel.go's loadPersistedTunnelTokens does at startup.
func TestTunnelTokenRegisterHandler_PersistsAcrossRestart(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)

	body, _ := json.Marshal(TunnelTokenRegisterRequest{Token: "byoc-token", Pools: []Pool{"asia-east1"}})
	req := httptest.NewRequest(http.MethodPost, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenRegisterHandler())
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// "Restart": a brand-new policy, as PolicyFromCLI would build at
	// startup, with none of this process's registrations.
	freshPolicy := NewTokenPolicy()
	if err := freshPolicy.Validate("byoc-token", "asia-east1"); err == nil {
		t.Fatal("sanity check: fresh policy should not yet know this token")
	}

	entries, err := LoadTunnelTokenStore(m.tunnelTokenStorePath)
	if err != nil {
		t.Fatalf("LoadTunnelTokenStore: %v", err)
	}
	ApplyTunnelTokenStore(entries, freshPolicy)

	if err := freshPolicy.Validate("byoc-token", "asia-east1"); err != nil {
		t.Fatalf("token must survive a restart via the persisted store: %v", err)
	}
	if err := freshPolicy.Validate("byoc-token", "us-west1"); err == nil {
		t.Fatal("token was scoped to asia-east1 only; pool restriction must survive too")
	}
}

func TestTunnelTokenRegisterHandler_RestrictsToSpecifiedPools(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)

	body, _ := json.Marshal(TunnelTokenRegisterRequest{Token: "scoped-token", Pools: []Pool{"lab"}})
	req := httptest.NewRequest(http.MethodPost, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenRegisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if err := m.tunnelPolicy.Validate("scoped-token", "lab"); err != nil {
		t.Fatalf("token should be valid for lab: %v", err)
	}
	if err := m.tunnelPolicy.Validate("scoped-token", "prod"); err == nil {
		t.Fatal("token should NOT be valid for prod")
	}
}

func TestTunnelTokenRegisterHandler_501WhenTunnelModeDisabled(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, false) // no SetTunnelPolicy call

	body, _ := json.Marshal(TunnelTokenRegisterRequest{Token: "x"})
	req := httptest.NewRequest(http.MethodPost, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenRegisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("want 501, got %d", rec.Code)
	}
}

func TestTunnelTokenRegisterHandler_400OnMissingToken(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)

	body, _ := json.Marshal(TunnelTokenRegisterRequest{})
	req := httptest.NewRequest(http.MethodPost, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenRegisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestTunnelTokenRegisterHandler_RejectsUnsignedRequest(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)

	body, _ := json.Marshal(TunnelTokenRegisterRequest{Token: "x"})
	req := httptest.NewRequest(http.MethodPost, "/sentinel/tunnel-tokens", bytes.NewReader(body)) // no SignSentinelRequest
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenRegisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned request must be rejected; got %d", rec.Code)
	}
}

// TestTunnelTokenRegisterHandler_AdminSecretIndependentOfHMACSecret guards
// the core security property of #799's fix: possessing the cluster-wide
// daemon HMAC secret (CONTAINARIUM_SENTINEL_AUTH_SECRET) must NOT be
// sufficient to register new tunnel-join tokens.
func TestTunnelTokenRegisterHandler_AdminSecretIndependentOfHMACSecret(t *testing.T) {
	m := &Manager{backends: NewBackendPool()}
	m.SetHMACSecret([]byte(phase05Secret)) // cluster-wide daemon secret
	m.SetAdminSecret([]byte(tunnelTokenAdminSecret))
	m.SetTunnelPolicy(NewTokenPolicy())

	body, _ := json.Marshal(TunnelTokenRegisterRequest{Token: "x"})
	req := httptest.NewRequest(http.MethodPost, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	auth.SignSentinelRequest(req, []byte(phase05Secret)) // signed with the WRONG secret
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware(m.adminSecret, m.TunnelTokenRegisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("HMAC secret must not authorize admin token registration; got %d", rec.Code)
	}
}
