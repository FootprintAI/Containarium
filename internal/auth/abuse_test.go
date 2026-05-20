package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Phase 5.4 — abuse-case regression tests. Each scenario
// names a class of attack the audit explicitly flagged and
// asserts that the daemon's defense holds. If any of these
// flip from "deny" to "allow" in a future refactor, the
// build breaks loudly. That's the point.
//
// These tests aren't trying to cover the full code path —
// per-layer tests already do that. They're a tripwire: a
// single regression here means an attack we already
// audited is suddenly viable again.

func abuseTokenManager(t *testing.T) *TokenManager {
	t.Helper()
	tm, err := NewTokenManager("abuse-suite-secret-key-at-least-32-bytes-long", "abuse-test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return tm
}

// --- Replayed revoked tokens (Phase 1.2) ---

func TestAbuse_RevokedTokenIsRejected(t *testing.T) {
	tm := abuseTokenManager(t)
	store := newAbuseStore()
	tm.SetRevocationStore(store)

	tok, err := tm.GenerateAccessToken("alice", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	claims, err := tm.ValidateAccessToken(tok)
	if err != nil {
		t.Fatalf("token should validate before revoke; got %v", err)
	}
	if err := tm.RevokeToken(context.Background(), claims, "abuse-test"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, err := tm.ValidateAccessToken(tok); err == nil {
		t.Fatal("revoked token must NOT validate on the API surface")
	}
}

// --- Refresh-token replay (Phase 1.6 rotation) ---

func TestAbuse_RefreshTokenSingleUse(t *testing.T) {
	// We can't drive the gRPC RefreshToken handler from this
	// package without cycles, but the underlying invariant
	// is simple: once a refresh token's jti is revoked,
	// ValidateRefreshToken refuses it. That's what the RPC
	// does on rotation. Asserting it here keeps the
	// invariant under test even if the RPC code is
	// restructured.
	tm := abuseTokenManager(t)
	store := newAbuseStore()
	tm.SetRevocationStore(store)

	refresh, _ := tm.GenerateRefreshToken("alice", []string{"user"}, time.Hour)
	claims, err := tm.ValidateRefreshToken(refresh)
	if err != nil {
		t.Fatalf("first validate: %v", err)
	}

	// Simulate rotation: the RPC revokes the prior refresh.
	if err := tm.RevokeToken(context.Background(), claims, "refresh_rotation"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	// Replay the same refresh — must fail.
	if _, err := tm.ValidateRefreshToken(refresh); err == nil {
		t.Fatal("replayed refresh token must be rejected after rotation")
	}
}

// --- Access token used at refresh endpoint (Phase 1.6) ---

func TestAbuse_AccessTokenAtRefreshPathRejected(t *testing.T) {
	tm := abuseTokenManager(t)
	tok, _ := tm.GenerateAccessToken("alice", []string{"user"}, time.Hour)
	if _, err := tm.ValidateRefreshToken(tok); err == nil {
		t.Fatal("access token must NOT pass ValidateRefreshToken")
	}
}

// --- Refresh token used on API surface (Phase 1.6) ---

func TestAbuse_RefreshTokenOnAPISurfaceRejected(t *testing.T) {
	tm := abuseTokenManager(t)
	refresh, _ := tm.GenerateRefreshToken("alice", []string{"user"}, time.Hour)
	if _, err := tm.ValidateAccessToken(refresh); err == nil {
		t.Fatal("refresh token must NOT pass ValidateAccessToken")
	}
}

// --- Wrong-tenant access (Phase 1.4 IDOR) ---

func TestAbuse_WrongTenantAccessDenied(t *testing.T) {
	ctx := ContextWithTestSubject(context.Background(), "alice", "user")
	if err := AuthorizeTenant(ctx, "bob"); err == nil {
		t.Fatal("alice must NOT authorize for bob")
	}
}

func TestAbuse_AdminCanAccessAnyTenant(t *testing.T) {
	// Counter-example so this test reads as a pair with the
	// rejection case: admin role lawfully passes per
	// AuthorizeTenant contract.
	ctx := ContextWithTestSubject(context.Background(), "ops", RoleAdmin)
	if err := AuthorizeTenant(ctx, "bob"); err != nil {
		t.Fatalf("admin should pass for any tenant; got %v", err)
	}
}

// --- Wrong-container access via container_name (Phase 1.4 follow-up) ---

func TestAbuse_WrongContainerAccessDenied(t *testing.T) {
	ctx := ContextWithTestSubject(context.Background(), "alice", "user")
	if err := AuthorizeContainerAccess(ctx, "bob-container"); err == nil {
		t.Fatal("alice must NOT authorize for bob-container")
	}
	if err := AuthorizeContainerAccess(ctx, "caddy"); err == nil {
		t.Fatal("non-admin must NOT authorize for system containers")
	}
}

// --- Scope confusion (Phase 1.7b) ---

func TestAbuse_NarrowScopedTokenCannotEscalate(t *testing.T) {
	// A token granted only containers:read must not pass a
	// containers:write gate, even if the role is admin.
	ctx := ContextWithTestSubjectScopes(context.Background(),
		"ops", []string{RoleAdmin},
		[]string{ScopeContainersRead},
	)
	if err := RequireScope(ctx, ScopeContainersWrite); err == nil {
		t.Fatal("admin with containers:read must NOT pass containers:write gate")
	}
	if err := RequireScope(ctx, ScopeSecretsRead); err == nil {
		t.Fatal("admin with containers:read must NOT pass secrets:read gate")
	}
}

// --- Algorithm confusion / token tampering (Phase 1.1) ---

func TestAbuse_TamperedTokenRejected(t *testing.T) {
	tm := abuseTokenManager(t)
	tok, _ := tm.GenerateAccessToken("alice", []string{"user"}, time.Hour)

	// Flip a single character in the signature segment.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token shape: %s", tok)
	}
	sig := []byte(parts[2])
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(sig)
	if _, err := tm.ValidateAccessToken(tampered); err == nil {
		t.Fatal("tampered signature must be rejected")
	}
}

func TestAbuse_AlgorithmNoneRejected(t *testing.T) {
	// Crafted token claiming alg=none. ValidateAccessToken
	// must refuse — the JWT alg pin landed in audit
	// C-CRIT-3.
	tm := abuseTokenManager(t)
	// header: {"alg":"none","typ":"JWT"} base64url
	header := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
	// payload: {"username":"alice","exp":99999999999}
	payload := "eyJ1c2VybmFtZSI6ImFsaWNlIiwiZXhwIjo5OTk5OTk5OTk5OX0"
	noneTok := header + "." + payload + "."
	if _, err := tm.ValidateAccessToken(noneTok); err == nil {
		t.Fatal("alg=none token must be rejected")
	}
}

// --- Failed-auth rate limiting (Phase 1.x C-MED-3) ---

func TestAbuse_FailedAuthRateLimited(t *testing.T) {
	// Spray ~20 invalid tokens from a single IP. After the
	// burst is exhausted the middleware must reject with
	// 429, not 401. (Default burst is 10 with 6/min refill;
	// 20 attempts in zero elapsed time guarantees at least
	// one 429.)
	tm := abuseTokenManager(t)
	mw := NewAuthMiddleware(tm)
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := mw.HTTPMiddleware(stub)

	saw429 := false
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("GET", "/v1/containers", nil)
		req.RemoteAddr = "203.0.113.42:55555"
		req.Header.Set("Authorization", "Bearer junk")
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}
	if !saw429 {
		t.Fatal("brute-force token spray should hit the per-IP rate limiter (429)")
	}
}

// --- Pre-1.7 token compat across the abuse surface ---

func TestAbuse_LegacyTokenStillWorks(t *testing.T) {
	// Backwards compat is a security property: if a refactor
	// breaks legacy tokens silently, operators get locked
	// out at 3am. Assert the basic flow.
	tm := abuseTokenManager(t)
	tok, _ := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	claims, err := tm.ValidateAccessToken(tok)
	if err != nil {
		t.Fatalf("legacy token: %v", err)
	}
	if claims.Username != "alice" {
		t.Fatalf("legacy claims username = %q", claims.Username)
	}
}

// --- in-memory revocation store for these tests ---

type abuseStore struct {
	mu      sync.Mutex
	revoked map[string]struct{}
}

func newAbuseStore() *abuseStore {
	return &abuseStore{revoked: map[string]struct{}{}}
}

func (a *abuseStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.revoked[jti]
	return ok, nil
}
func (a *abuseStore) Revoke(_ context.Context, jti string, _ time.Time, _ string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revoked[jti] = struct{}{}
	return nil
}
func (a *abuseStore) CleanupExpired(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
