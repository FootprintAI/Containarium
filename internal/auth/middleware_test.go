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
