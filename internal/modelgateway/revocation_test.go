package modelgateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRevocations is a stub revocation store. `err` makes every lookup fail, so
// the fail-open path is exercised without a real database.
type fakeRevocations struct {
	mu      sync.Mutex
	revoked map[string]bool
	err     error
	asked   []string
}

func newFakeRevocations() *fakeRevocations {
	return &fakeRevocations{revoked: map[string]bool{}}
}

func (f *fakeRevocations) IsRevoked(_ context.Context, jti string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, jti)
	if f.err != nil {
		return false, f.err
	}
	return f.revoked[jti], nil
}

func (f *fakeRevocations) revoke(jti string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked[jti] = true
}

func (f *fakeRevocations) lookups() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

// revocationHarness builds a gateway whose upstream counts hits, so every test
// can assert the thing that actually matters: a refused call must not reach the
// provider, because that is where the real key is injected.
type revocationHarness struct {
	srv    *httptest.Server
	secret []byte
	hits   *int64
	revs   *fakeRevocations
}

func newRevocationHarness(t *testing.T, revs *fakeRevocations) *revocationHarness {
	t.Helper()
	secret := []byte("shared-secret")
	var hits int64
	up := fakeUpstream(t, func(*http.Request) { atomic.AddInt64(&hits, 1) },
		`{"model":"claude-test","usage":{"input_tokens":1,"output_tokens":1}}`)
	t.Cleanup(up.Close)

	providers := DefaultProviders()
	providers["anthropic"].UpstreamURL = up.URL

	cfg := Config{
		Secret: secret, Providers: providers,
		ProviderKeys: map[string]string{"anthropic": "REAL-KEY"},
	}
	// Deliberately assigned only when non-nil: passing a typed nil would make
	// the interface non-nil and defeat the gateway's own nil guard.
	if revs != nil {
		cfg.Revocations = revs
	}
	srv := httptest.NewServer(New(cfg).Handler())
	t.Cleanup(srv.Close)

	return &revocationHarness{srv: srv, secret: secret, hits: &hits, revs: revs}
}

func (h *revocationHarness) call(t *testing.T, tok string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", h.srv.URL+"/v1/model/anthropic/v1/messages",
		strings.NewReader(`{"model":"claude-test"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func (h *revocationHarness) upstreamHits() int64 { return atomic.LoadInt64(h.hits) }

// mintAndRead mints a token and recovers its jti, since revoking one means
// knowing the id the mint generated.
func mintAndRead(t *testing.T, secret []byte, c GatewayClaims, ttl time.Duration) (string, string) {
	t.Helper()
	tok, err := MintToken(secret, c, ttl)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyToken(secret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ID == "" {
		t.Fatal("minted token carries no jti — nothing to revoke")
	}
	return tok, claims.ID
}

// The point of the whole change: a revoked token stops working before its TTL,
// and never reaches the provider.
func TestGateway_RevokedTokenIsRefused(t *testing.T) {
	revs := newFakeRevocations()
	h := newRevocationHarness(t, revs)

	// A year-long token, the shape a recipe box actually gets.
	tok, jti := mintAndRead(t, h.secret, GatewayClaims{Tenant: "acme", Provider: "anthropic"}, 365*24*time.Hour)

	if got := h.call(t, tok).StatusCode; got != http.StatusOK {
		t.Fatalf("pre-revocation status = %d, want 200", got)
	}
	if h.upstreamHits() != 1 {
		t.Fatalf("upstream hits = %d, want 1", h.upstreamHits())
	}

	revs.revoke(jti)

	resp := h.call(t, tok)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("post-revocation status = %d, want 401", resp.StatusCode)
	}
	if got := h.upstreamHits(); got != 1 {
		t.Errorf("upstream hits = %d, want 1 — a revoked token reached the provider", got)
	}
}

// Revoking one token must not affect another, including one for the same
// tenant. This is the property the in-memory tenant-level brake cannot give.
func TestGateway_RevocationIsPerToken(t *testing.T) {
	revs := newFakeRevocations()
	h := newRevocationHarness(t, revs)

	leaked, leakedJTI := mintAndRead(t, h.secret, GatewayClaims{Tenant: "acme", Provider: "anthropic"}, time.Hour)
	good, _ := mintAndRead(t, h.secret, GatewayClaims{Tenant: "acme", Provider: "anthropic"}, time.Hour)

	revs.revoke(leakedJTI)

	if got := h.call(t, leaked).StatusCode; got != http.StatusUnauthorized {
		t.Errorf("revoked token status = %d, want 401", got)
	}
	if got := h.call(t, good).StatusCode; got != http.StatusOK {
		t.Errorf("sibling token status = %d, want 200 — revoking one token killed the tenant", got)
	}
}

// A database outage must not take every tenant's model traffic down with it.
// By this point the signature, issuer, expiry, tenant binding and model ceiling
// have all been checked, so failing open degrades to the protection that
// existed before this check, rather than to an outage.
func TestGateway_RevocationLookupFailureFailsOpen(t *testing.T) {
	revs := newFakeRevocations()
	revs.err = errors.New("connection refused")
	h := newRevocationHarness(t, revs)

	tok, _ := mintAndRead(t, h.secret, GatewayClaims{Tenant: "acme", Provider: "anthropic"}, time.Hour)

	if got := h.call(t, tok).StatusCode; got != http.StatusOK {
		t.Errorf("status = %d, want 200 — a revocation-store outage must not block model traffic", got)
	}
	if got := h.upstreamHits(); got != 1 {
		t.Errorf("upstream hits = %d, want 1", got)
	}
}

// No store configured (a standalone daemon with no Postgres) must behave
// exactly as before the check existed.
func TestGateway_NoRevocationStoreConfigured(t *testing.T) {
	h := newRevocationHarness(t, nil)

	tok, _ := mintAndRead(t, h.secret, GatewayClaims{Tenant: "acme", Provider: "anthropic"}, time.Hour)
	for i := 0; i < 3; i++ {
		if got := h.call(t, tok).StatusCode; got != http.StatusOK {
			t.Fatalf("call %d status = %d, want 200 with no revocation store", i, got)
		}
	}
	if got := h.upstreamHits(); got != 3 {
		t.Errorf("upstream hits = %d, want 3", got)
	}
}

// An empty jti must not cost a lookup. Tokens minted before jti existed carry
// none, and asking the store about "" is a pointless round trip on every call.
func TestGateway_EmptyJTISkipsTheLookup(t *testing.T) {
	revs := newFakeRevocations()
	gw := New(Config{
		Secret:       []byte("s"),
		Providers:    DefaultProviders(),
		ProviderKeys: map[string]string{"anthropic": "K"},
		Revocations:  revs,
	})

	if gw.isRevoked(context.Background(), "") {
		t.Error("empty jti reported as revoked")
	}
	if got := revs.lookups(); len(got) != 0 {
		t.Errorf("lookups = %v, want none for an empty jti", got)
	}

	// A real id is looked up.
	if gw.isRevoked(context.Background(), "abc123") {
		t.Error("unrevoked jti reported as revoked")
	}
	if got := revs.lookups(); len(got) != 1 || got[0] != "abc123" {
		t.Errorf("lookups = %v, want [abc123]", got)
	}
}

// The check must not be reachable only through the happy path: a token for the
// wrong provider is already refused earlier, and that must stay true.
func TestGateway_RevocationDoesNotDisturbExistingChecks(t *testing.T) {
	revs := newFakeRevocations()
	h := newRevocationHarness(t, revs)

	tok, _ := mintAndRead(t, h.secret, GatewayClaims{Tenant: "acme", Provider: "openai"}, time.Hour)

	// Presented against anthropic: refused on the provider check, before the
	// revocation lookup is reached.
	if got := h.call(t, tok).StatusCode; got != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a provider mismatch", got)
	}
	if got := revs.lookups(); len(got) != 0 {
		t.Errorf("revocation was consulted for a request refused earlier: %v", got)
	}
	if got := h.upstreamHits(); got != 0 {
		t.Errorf("upstream hits = %d, want 0", got)
	}
}
