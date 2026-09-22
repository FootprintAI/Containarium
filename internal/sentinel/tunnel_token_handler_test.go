package sentinel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
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

// TestTunnelTokenRegisterHandler_PersistFailureIsAServerErrorNot204 (#1772):
// reporting 204 when the durable record wasn't actually written told the
// caller its token was safely registered when it wasn't — the gap only
// surfaced days later, indirectly, as an unexplained permanent disconnect
// after an unrelated sentinel restart, with no error at the time it
// mattered and no signal at restart time either. Same shape as the
// deregister side's existing guard
// (TestTunnelTokenDeregisterHandler_PersistFailureIsAServerErrorNot204):
// the in-memory Allow must still take effect immediately (the safe
// direction — a disk hiccup must not drop a legitimate, just-joined host's
// live tunnel session) even though the response reports failure, so a
// retry lands on the same idempotent Allow and gets a fresh chance to
// persist.
func TestTunnelTokenRegisterHandler_PersistFailureIsAServerErrorNot204(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)

	// Force SaveTunnelTokenStore to fail: point the store path at
	// "<blocker-file>/tunnel-tokens.json", so its os.MkdirAll(dir) fails
	// because "blocker" already exists as a regular file, not a directory.
	blocker := t.TempDir() + "/blocker"
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("create blocker file: %v", err)
	}
	m.SetTunnelTokenStorePath(blocker + "/tunnel-tokens.json")

	body, _ := json.Marshal(TunnelTokenRegisterRequest{Token: "fresh-token"})
	req := httptest.NewRequest(http.MethodPost, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenRegisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 when persistence fails, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := m.tunnelPolicy.Validate("fresh-token", ""); err != nil {
		t.Fatalf("token must still be allowed in-memory even though the response reported a persist failure: %v", err)
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

// TestTunnelTokenDeregisterHandler_RemovesARegisteredToken is the whole
// point of #999 step 4: a token the sentinel currently accepts must stop
// validating after deregistration, the exact inverse of
// TestTunnelTokenRegisterHandler_RegistersFreshToken.
func TestTunnelTokenDeregisterHandler_RemovesARegisteredToken(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)
	m.tunnelPolicy.Allow("live-token", PoolAny)
	if err := m.tunnelPolicy.Validate("live-token", ""); err != nil {
		t.Fatalf("sanity check: token should validate before deregistration: %v", err)
	}

	body, _ := json.Marshal(TunnelTokenDeregisterRequest{Token: "live-token"})
	req := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenDeregisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if err := m.tunnelPolicy.Validate("live-token", ""); err == nil {
		t.Fatal("token still valid after deregistration")
	}
}

// TestTunnelTokenDeregisterHandler_PersistsAcrossRestart: the inverse of
// TestTunnelTokenRegisterHandler_PersistsAcrossRestart — a deregistered
// token must not come back after a restart re-applies the persisted store.
func TestTunnelTokenDeregisterHandler_PersistsAcrossRestart(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)

	registerBody, _ := json.Marshal(TunnelTokenRegisterRequest{Token: "byoc-token", Pools: []Pool{"asia-east1"}})
	registerReq := httptest.NewRequest(http.MethodPost, "/sentinel/tunnel-tokens", bytes.NewReader(registerBody))
	registerReq.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(registerReq, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenRegisterHandler()).ServeHTTP(rec, registerReq)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("register status = %d, body = %s", rec.Code, rec.Body.String())
	}

	deregisterBody, _ := json.Marshal(TunnelTokenDeregisterRequest{Token: "byoc-token"})
	deregisterReq := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(deregisterBody))
	deregisterReq.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(deregisterReq, []byte(tunnelTokenAdminSecret))
	rec = httptest.NewRecorder()
	auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenDeregisterHandler()).ServeHTTP(rec, deregisterReq)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("deregister status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// "Restart": a brand-new policy loaded from the persisted store, as
	// internal/cmd/sentinel.go's loadPersistedTunnelTokens does at startup.
	freshPolicy := NewTokenPolicy()
	entries, err := LoadTunnelTokenStore(m.tunnelTokenStorePath)
	if err != nil {
		t.Fatalf("LoadTunnelTokenStore: %v", err)
	}
	ApplyTunnelTokenStore(entries, freshPolicy)

	if err := freshPolicy.Validate("byoc-token", "asia-east1"); err == nil {
		t.Fatal("deregistered token came back after a simulated restart — the removal did not persist")
	}
}

func TestTunnelTokenDeregisterHandler_501WhenTunnelModeDisabled(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, false) // no SetTunnelPolicy call

	body, _ := json.Marshal(TunnelTokenDeregisterRequest{Token: "x"})
	req := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenDeregisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("want 501, got %d", rec.Code)
	}
}

func TestTunnelTokenDeregisterHandler_400OnMissingToken(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)

	body, _ := json.Marshal(TunnelTokenDeregisterRequest{})
	req := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenDeregisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestTunnelTokenDeregisterHandler_RejectsUnsignedRequest(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)

	body, _ := json.Marshal(TunnelTokenDeregisterRequest{Token: "x"})
	req := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(body)) // no SignSentinelRequest
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenDeregisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned request must be rejected; got %d", rec.Code)
	}
}

// TestTunnelTokenDeregisterHandler_UnknownTokenIsNoContentNotError:
// deregistering a token that isn't currently registered must succeed —
// decommission callers cannot know in advance whether registration ever
// landed (e.g. the register call itself failed, or this is a retry), and
// the end state ("this token does not validate") is identical either way.
func TestTunnelTokenDeregisterHandler_UnknownTokenIsNoContentNotError(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)

	body, _ := json.Marshal(TunnelTokenDeregisterRequest{Token: "never-registered"})
	req := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenDeregisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204 for an already-absent token, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestTunnelTokenDeregisterHandler_PersistFailureIsAServerErrorNot204 is
// the review follow-up on cloud#999 step 4: reporting 204 when the durable
// record wasn't actually written would tell a decommission caller "done"
// for a token that WILL reappear after the next restart, with no reason
// to retry. The in-memory Deny must still take effect immediately (the
// safe direction) even though the response reports failure.
func TestTunnelTokenDeregisterHandler_PersistFailureIsAServerErrorNot204(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)
	m.tunnelPolicy.Allow("live-token", PoolAny)

	// Force SaveTunnelTokenStore to fail: point the store path at
	// "<blocker-file>/tunnel-tokens.json", so its os.MkdirAll(dir) fails
	// because "blocker" already exists as a regular file, not a directory.
	blocker := t.TempDir() + "/blocker"
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("create blocker file: %v", err)
	}
	m.SetTunnelTokenStorePath(blocker + "/tunnel-tokens.json")

	body, _ := json.Marshal(TunnelTokenDeregisterRequest{Token: "live-token"})
	req := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenDeregisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 when persistence fails, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := m.tunnelPolicy.Validate("live-token", ""); err == nil {
		t.Fatal("token must still be denied in-memory even though the response reported a persist failure")
	}
}

// TestTunnelTokenDeregisterHandler_AdminSecretIndependentOfHMACSecret is
// the deregister sibling of the same register-side guard: possessing the
// cluster-wide daemon HMAC secret must not be sufficient to deregister
// another host's tunnel token — that would let any enrolled daemon knock
// any other host off its tunnel.
func TestTunnelTokenDeregisterHandler_AdminSecretIndependentOfHMACSecret(t *testing.T) {
	m := &Manager{backends: NewBackendPool()}
	m.SetHMACSecret([]byte(phase05Secret)) // cluster-wide daemon secret
	m.SetAdminSecret([]byte(tunnelTokenAdminSecret))
	m.SetTunnelPolicy(NewTokenPolicy())

	body, _ := json.Marshal(TunnelTokenDeregisterRequest{Token: "x"})
	req := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	auth.SignSentinelRequest(req, []byte(phase05Secret)) // signed with the WRONG secret
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware(m.adminSecret, m.TunnelTokenDeregisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("HMAC secret must not authorize admin token deregistration; got %d", rec.Code)
	}
}

// TestTunnelTokenDeregisterHandler_AndRegisterCoexistOnOneMux confirms the
// two handlers can be mounted on the SAME path (POST=register,
// DELETE=deregister via Go 1.22+ ServeMux method patterns) without either
// one intercepting the other's method — a routing-wiring regression here
// would silently 405 one side.
func TestTunnelTokenDeregisterHandler_AndRegisterCoexistOnOneMux(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)
	mux := http.NewServeMux()
	mux.Handle("/sentinel/tunnel-tokens", auth.SentinelHMACMiddleware(m.adminSecret, m.TunnelTokenRegisterHandler()))
	mux.Handle("DELETE /sentinel/tunnel-tokens", auth.SentinelHMACMiddleware(m.adminSecret, m.TunnelTokenDeregisterHandler()))

	registerBody, _ := json.Marshal(TunnelTokenRegisterRequest{Token: "mux-token"})
	registerReq := httptest.NewRequest(http.MethodPost, "/sentinel/tunnel-tokens", bytes.NewReader(registerBody))
	registerReq.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(registerReq, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, registerReq)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("register via mux: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if err := m.tunnelPolicy.Validate("mux-token", ""); err != nil {
		t.Fatalf("token not registered via mux: %v", err)
	}

	deregisterBody, _ := json.Marshal(TunnelTokenDeregisterRequest{Token: "mux-token"})
	deregisterReq := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(deregisterBody))
	deregisterReq.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(deregisterReq, []byte(tunnelTokenAdminSecret))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, deregisterReq)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("deregister via mux: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if err := m.tunnelPolicy.Validate("mux-token", ""); err == nil {
		t.Fatal("token still valid after deregistration via mux")
	}
}

// TestConcurrentRegisterAndDeregister_NoLostUpdates is the regression test
// for the CodeRabbit review follow-up on cloud#999 step 4: persist/unpersist
// each do an unserialized load-modify-save against the SAME on-disk file,
// so a register racing a deregister (or two concurrent calls of either)
// could read the same snapshot and have whichever writes second silently
// discard the other's change. Runs enough concurrent registrations that a
// lost update would show up as a missing entry in the final store; with
// tunnelTokenStoreMu serializing the whole sequence, none can be lost.
func TestConcurrentRegisterAndDeregister_NoLostUpdates(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)
	const n = 50

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token := fmt.Sprintf("concurrent-token-%d", i)
			body, _ := json.Marshal(TunnelTokenRegisterRequest{Token: token})
			req := httptest.NewRequest(http.MethodPost, "/sentinel/tunnel-tokens", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
			rec := httptest.NewRecorder()
			m.TunnelTokenRegisterHandler()(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Errorf("register %s: status = %d", token, rec.Code)
			}
		}(i)
	}
	wg.Wait()

	entries, err := LoadTunnelTokenStore(m.tunnelTokenStorePath)
	if err != nil {
		t.Fatalf("LoadTunnelTokenStore: %v", err)
	}
	if len(entries) != n {
		t.Fatalf("persisted store has %d entries, want %d — concurrent registrations lost an update", len(entries), n)
	}

	// Now deregister half of them concurrently, alongside no further
	// registrations, and confirm exactly the other half survives.
	wg = sync.WaitGroup{}
	for i := 0; i < n; i += 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token := fmt.Sprintf("concurrent-token-%d", i)
			body, _ := json.Marshal(TunnelTokenDeregisterRequest{Token: token})
			req := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
			rec := httptest.NewRecorder()
			m.TunnelTokenDeregisterHandler()(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Errorf("deregister %s: status = %d", token, rec.Code)
			}
		}(i)
	}
	wg.Wait()

	entries, err = LoadTunnelTokenStore(m.tunnelTokenStorePath)
	if err != nil {
		t.Fatalf("LoadTunnelTokenStore after deregister: %v", err)
	}
	if len(entries) != n/2 {
		t.Fatalf("persisted store has %d entries after deregistering half, want %d — a concurrent deregister lost an update or a register reappeared", len(entries), n/2)
	}
	for _, e := range entries {
		var idx int
		if _, err := fmt.Sscanf(e.Token, "concurrent-token-%d", &idx); err != nil {
			t.Fatalf("unexpected surviving token %q", e.Token)
		}
		if idx%2 == 0 {
			t.Errorf("token %q should have been deregistered but survived", e.Token)
		}
	}
}

// TestTunnelTokenDeregisterHandler_RemovesEveryTokenSharingPrefix is the
// whole point of #1963: a control plane that mints a join token but never
// retains the plaintext (the correct posture — it hands the token to the
// operator once and keeps only a hash) has nothing to put in {"token":...}
// when it wants to decommission a host. It knows the host id, so it must be
// able to deregister by {"token_prefix": "<host-id>."} instead, and that one
// call must remove BOTH the original join token and a reissued reconnect
// token sharing the same host-id prefix — without the caller ever supplying
// either plaintext token.
func TestTunnelTokenDeregisterHandler_RemovesEveryTokenSharingPrefix(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)
	m.tunnelPolicy.Allow("host-a.secret1", PoolAny) // original join token
	m.tunnelPolicy.Allow("host-a.secret2", PoolAny) // reissued reconnect token
	m.tunnelPolicy.Allow("host-b.secret1", PoolAny) // different host, must survive

	body, _ := json.Marshal(TunnelTokenDeregisterRequest{TokenPrefix: "host-a."})
	req := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenDeregisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if err := m.tunnelPolicy.Validate("host-a.secret1", ""); err == nil {
		t.Fatal("original join token still valid after prefix deregistration")
	}
	if err := m.tunnelPolicy.Validate("host-a.secret2", ""); err == nil {
		t.Fatal("reissued reconnect token still valid after prefix deregistration")
	}
	if err := m.tunnelPolicy.Validate("host-b.secret1", ""); err != nil {
		t.Fatalf("a different host's token must survive: %v", err)
	}
}

// TestTunnelTokenDeregisterHandler_PrefixPersistsAcrossRestart is the
// prefix-form sibling of TestTunnelTokenDeregisterHandler_PersistsAcrossRestart
// — the removal must go through the same persist path so it survives a
// sentinel restart, not just apply to the current process's in-memory
// policy.
func TestTunnelTokenDeregisterHandler_PrefixPersistsAcrossRestart(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)

	for _, tok := range []string{"host-a.secret1", "host-a.secret2"} {
		registerBody, _ := json.Marshal(TunnelTokenRegisterRequest{Token: tok, Pools: []Pool{"asia-east1"}})
		registerReq := httptest.NewRequest(http.MethodPost, "/sentinel/tunnel-tokens", bytes.NewReader(registerBody))
		registerReq.Header.Set("Content-Type", "application/json")
		auth.SignSentinelRequest(registerReq, []byte(tunnelTokenAdminSecret))
		rec := httptest.NewRecorder()
		auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenRegisterHandler()).ServeHTTP(rec, registerReq)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("register %s status = %d, body = %s", tok, rec.Code, rec.Body.String())
		}
	}

	deregisterBody, _ := json.Marshal(TunnelTokenDeregisterRequest{TokenPrefix: "host-a."})
	deregisterReq := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(deregisterBody))
	deregisterReq.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(deregisterReq, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenDeregisterHandler()).ServeHTTP(rec, deregisterReq)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("deregister status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// "Restart": a brand-new policy loaded from the persisted store.
	freshPolicy := NewTokenPolicy()
	entries, err := LoadTunnelTokenStore(m.tunnelTokenStorePath)
	if err != nil {
		t.Fatalf("LoadTunnelTokenStore: %v", err)
	}
	ApplyTunnelTokenStore(entries, freshPolicy)

	if err := freshPolicy.Validate("host-a.secret1", "asia-east1"); err == nil {
		t.Fatal("prefix-deregistered token came back after a simulated restart — the removal did not persist")
	}
	if err := freshPolicy.Validate("host-a.secret2", "asia-east1"); err == nil {
		t.Fatal("prefix-deregistered reissued token came back after a simulated restart — the removal did not persist")
	}
}

// TestTunnelTokenDeregisterHandler_PrefixMatchingNothingIsNoContent mirrors
// TestTunnelTokenDeregisterHandler_UnknownTokenIsNoContentNotError for the
// prefix form: the caller cannot know in advance whether any token under
// that host id was ever registered, and the end state is identical either
// way.
func TestTunnelTokenDeregisterHandler_PrefixMatchingNothingIsNoContent(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)

	body, _ := json.Marshal(TunnelTokenDeregisterRequest{TokenPrefix: "never-registered."})
	req := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenDeregisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204 for a prefix matching nothing, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestTunnelTokenDeregisterHandler_400OnPrefixWithoutTrailingDot pins the
// exact footgun called out in #1963: "abc" must not match "abcd.xyz", so a
// token_prefix missing its trailing "." is rejected outright rather than
// silently matching more than the caller intended.
func TestTunnelTokenDeregisterHandler_400OnPrefixWithoutTrailingDot(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)
	m.tunnelPolicy.Allow("abcd.xyz", PoolAny)

	body, _ := json.Marshal(TunnelTokenDeregisterRequest{TokenPrefix: "abc"})
	req := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenDeregisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for a prefix without a trailing dot, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := m.tunnelPolicy.Validate("abcd.xyz", ""); err != nil {
		t.Fatalf("rejected prefix must not have touched the policy: %v", err)
	}
}

// TestTunnelTokenDeregisterHandler_400OnEmptyPrefix: an explicit empty
// string for token_prefix is the same "nothing to key on" case as an
// entirely missing token/token_prefix.
func TestTunnelTokenDeregisterHandler_400OnEmptyPrefix(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)

	body, _ := json.Marshal(TunnelTokenDeregisterRequest{TokenPrefix: ""})
	req := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenDeregisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for an empty token_prefix (and empty token), got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestTunnelTokenDeregisterHandler_400OnBothTokenAndPrefix: the request must
// key on exactly one identifier — supplying both is ambiguous about which
// removal semantics the caller wants and is rejected rather than guessed at.
func TestTunnelTokenDeregisterHandler_400OnBothTokenAndPrefix(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)
	m.tunnelPolicy.Allow("host-a.secret1", PoolAny)

	body, _ := json.Marshal(TunnelTokenDeregisterRequest{Token: "host-a.secret1", TokenPrefix: "host-a."})
	req := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenDeregisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 when both token and token_prefix are set, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestTunnelTokenDeregisterHandler_PrefixPersistFailureIsAServerErrorNot204
// is the prefix-form sibling of
// TestTunnelTokenDeregisterHandler_PersistFailureIsAServerErrorNot204: the
// in-memory DenyPrefix must still take effect immediately even though the
// response reports a persistence failure (the safe direction), and the
// caller must be told to retry rather than believing 204.
func TestTunnelTokenDeregisterHandler_PrefixPersistFailureIsAServerErrorNot204(t *testing.T) {
	m := newManagerForTunnelTokenTest(t, true)
	m.tunnelPolicy.Allow("host-a.secret1", PoolAny)

	blocker := t.TempDir() + "/blocker"
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("create blocker file: %v", err)
	}
	m.SetTunnelTokenStorePath(blocker + "/tunnel-tokens.json")

	body, _ := json.Marshal(TunnelTokenDeregisterRequest{TokenPrefix: "host-a."})
	req := httptest.NewRequest(http.MethodDelete, "/sentinel/tunnel-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(tunnelTokenAdminSecret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(tunnelTokenAdminSecret), m.TunnelTokenDeregisterHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 when persistence fails, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := m.tunnelPolicy.Validate("host-a.secret1", ""); err == nil {
		t.Fatal("token must still be denied in-memory even though the response reported a persist failure")
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
