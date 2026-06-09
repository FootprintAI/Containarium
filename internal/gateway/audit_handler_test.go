package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// Phase 1.5 — audit endpoint must require Authorization: Bearer
// and reject the legacy `?token=...` query-string form (audit
// finding A-MED-3). Query strings get logged by every reverse
// proxy in the request path, which silently re-leaked the admin
// token to anyone with log access.

const auditTestSecret = "a-secret-that-is-at-least-32-bytes-long!!"

func newAuditTestMux(t *testing.T) (*http.ServeMux, *auth.AuthMiddleware, string) {
	t.Helper()
	tm, err := auth.NewTokenManager(auditTestSecret, "containarium")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	tok, err := tm.GenerateToken("alice", []string{"admin"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	mw := auth.NewAuthMiddleware(tm)

	mux := http.NewServeMux()
	// nil store is acceptable: the auth check runs BEFORE we
	// touch the store, so an unauthenticated request returns 401
	// and never reaches handleAuditQuery. The authenticated path
	// would NPE without a real store, which we don't exercise.
	registerAuditEndpoint(mux, nil, mw)
	return mux, mw, tok
}

func TestAuditEndpoint_RejectsMissingAuth(t *testing.T) {
	mux, _, _ := newAuditTestMux(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/audit/logs", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAuditEndpoint_RejectsQueryStringToken(t *testing.T) {
	mux, _, tok := newAuditTestMux(t)
	// Old (vulnerable) pattern: token in URL query string.
	req := httptest.NewRequest("GET", "/v1/audit/logs?token="+tok, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("query-string token must be rejected; got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Authorization header") {
		t.Fatalf("error should point operator at the header: %s", rec.Body.String())
	}
}

func TestAuditEndpoint_RejectsMalformedAuthHeader(t *testing.T) {
	mux, _, tok := newAuditTestMux(t)
	cases := []struct {
		name   string
		header string
	}{
		{"empty", ""},
		{"no bearer prefix", tok},
		{"wrong scheme", "Basic " + tok},
		{"lowercase bearer", "bearer " + tok},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/v1/audit/logs", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s: status = %d, want 401", tc.name, rec.Code)
			}
		})
	}
}

func TestAuditEndpoint_RejectsInvalidToken(t *testing.T) {
	mux, _, _ := newAuditTestMux(t)
	req := httptest.NewRequest("GET", "/v1/audit/logs", nil)
	req.Header.Set("Authorization", "Bearer garbage.not-a-jwt.signature")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token must be rejected; got %d", rec.Code)
	}
}

// #621 — the audit log is sensitive (who-did-what across tenants), so a
// valid-but-non-admin token without an explicit audit:read scope is now
// forbidden (was: any valid token could read). The auth/scope check runs
// before the store, so this exercises the gate with a nil store. The
// allowed paths (admin role, or audit:read scope) reach handleAuditQuery
// and need a live store — covered in the audit store integration test.
func TestAuditEndpoint_RejectsValidNonAdminWithoutScope(t *testing.T) {
	tm, err := auth.NewTokenManager(auditTestSecret, "containarium")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	// Valid token, non-admin role, an unrelated scope — no audit:read.
	tok, err := tm.GenerateToken("alice", []string{"user"}, time.Hour, auth.ScopeContainersRead)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	mux := http.NewServeMux()
	registerAuditEndpoint(mux, nil, auth.NewAuthMiddleware(tm))

	req := httptest.NewRequest("GET", "/v1/audit/logs", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin without audit:read must be forbidden; got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "audit:read") {
		t.Fatalf("error should name the required scope: %s", rec.Body.String())
	}
}

// Note: a positive test that a valid token actually serves an
// audit-log response requires a live Postgres connection (the
// audit store). That coverage lives in
// internal/audit/store_integration_test.go. Here we only confirm
// that the auth-layer behaves correctly.
