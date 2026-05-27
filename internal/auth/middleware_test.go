package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHTTPMiddleware_AuthGate is the regression test for the
// /v1/backends auth fix and any future endpoint that wraps a handler
// with HTTPMiddleware. Proves the gate rejects missing / malformed /
// invalid tokens, and lets through valid ones.
//
// Why this test lives here and not in internal/gateway: the wrapping
// is one line in the gateway, and what's actually being verified is
// the middleware's contract. A handler wrapped with HTTPMiddleware
// MUST reject anonymous requests — every endpoint that relies on this
// (containers, backends, audit logs, …) inherits the same protection.
func TestHTTPMiddleware_AuthGate(t *testing.T) {
	tm, _ := NewTokenManager("test-secret-key-for-auth-middleware-test", "test-issuer")
	mw := NewAuthMiddleware(tm)

	// Stub handler that records whether it was called. If the auth
	// middleware lets a request through unauthenticated, this flips
	// true and the test fails.
	called := false
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	})
	wrapped := mw.HTTPMiddleware(stub)

	cases := []struct {
		name      string
		setup     func(r *http.Request)
		wantCode  int
		wantStub  bool // did the wrapped handler run?
	}{
		{
			name:     "no auth header → 401",
			setup:    func(r *http.Request) {},
			wantCode: http.StatusUnauthorized,
			wantStub: false,
		},
		{
			name: "wrong scheme (Basic) → 401",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
			},
			wantCode: http.StatusUnauthorized,
			wantStub: false,
		},
		{
			name: "Bearer with junk token → 401",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer not.a.real.jwt")
			},
			wantCode: http.StatusUnauthorized,
			wantStub: false,
		},
		{
			name: "Bearer with valid token → 200, handler runs",
			setup: func(r *http.Request) {
				token, err := tm.GenerateToken("test-user", []string{"admin"}, 5*time.Minute)
				if err != nil {
					t.Fatalf("GenerateToken: %v", err)
				}
				r.Header.Set("Authorization", "Bearer "+token)
			},
			wantCode: http.StatusOK,
			wantStub: true,
		},
		{
			// Phase 1.6 — refresh tokens must NOT authenticate
			// API requests. They can only be exchanged at the
			// (future) refresh RPC. A stolen refresh token is
			// therefore unusable against the API directly.
			name: "Bearer with refresh token → 401, handler does NOT run",
			setup: func(r *http.Request) {
				token, err := tm.GenerateRefreshToken("test-user", []string{"admin"}, 5*time.Minute)
				if err != nil {
					t.Fatalf("GenerateRefreshToken: %v", err)
				}
				r.Header.Set("Authorization", "Bearer "+token)
			},
			wantCode: http.StatusUnauthorized,
			wantStub: false,
		},
		{
			// Pre-1.6 tokens (no tt claim) must keep working.
			name: "Bearer with access-typed token → 200",
			setup: func(r *http.Request) {
				token, err := tm.GenerateAccessToken("test-user", []string{"admin"}, 5*time.Minute)
				if err != nil {
					t.Fatalf("GenerateAccessToken: %v", err)
				}
				r.Header.Set("Authorization", "Bearer "+token)
			},
			wantCode: http.StatusOK,
			wantStub: true,
		},
		{
			// Issue #338 — browser iframe carries the JWT in a
			// cookie (Authorization header is impossible to set on
			// <iframe src=...>). Valid cookie should authenticate.
			name: "cookie with valid access token → 200",
			setup: func(r *http.Request) {
				token, err := tm.GenerateAccessToken("test-user", []string{"admin"}, 5*time.Minute)
				if err != nil {
					t.Fatalf("GenerateAccessToken: %v", err)
				}
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
			},
			wantCode: http.StatusOK,
			wantStub: true,
		},
		{
			name: "cookie with junk value → 401",
			setup: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "not.a.real.jwt"})
			},
			wantCode: http.StatusUnauthorized,
			wantStub: false,
		},
		{
			// A stolen refresh token must NOT authenticate via the
			// cookie path either — same Phase 1.6 contract as the
			// header path.
			name: "cookie with refresh token → 401",
			setup: func(r *http.Request) {
				token, err := tm.GenerateRefreshToken("test-user", []string{"admin"}, 5*time.Minute)
				if err != nil {
					t.Fatalf("GenerateRefreshToken: %v", err)
				}
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
			},
			wantCode: http.StatusUnauthorized,
			wantStub: false,
		},
		{
			// Bearer takes precedence: if a junk header is set
			// alongside a valid cookie, the header decides (and
			// fails). Otherwise an attacker could mask a stolen
			// cookie's permissions by pasting a junk header.
			name: "junk Authorization header beats valid cookie → 401",
			setup: func(r *http.Request) {
				token, err := tm.GenerateAccessToken("test-user", []string{"admin"}, 5*time.Minute)
				if err != nil {
					t.Fatalf("GenerateAccessToken: %v", err)
				}
				r.Header.Set("Authorization", "Bearer not.a.real.jwt")
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
			},
			wantCode: http.StatusUnauthorized,
			wantStub: false,
		},
		{
			// Empty cookie value is the same as no cookie — fall
			// through to "missing authorization header".
			name: "empty cookie → 401",
			setup: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: ""})
			},
			wantCode: http.StatusUnauthorized,
			wantStub: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			req := httptest.NewRequest("GET", "/v1/backends", nil)
			tc.setup(req)
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d (body=%s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			if called != tc.wantStub {
				t.Errorf("inner handler called = %v, want %v", called, tc.wantStub)
			}
		})
	}
}
