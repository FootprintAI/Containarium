package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"google.golang.org/grpc/metadata"
)

// End-to-end claim propagation: a JWT bearer carrying a
// scopes claim must end up in the gRPC server's incoming
// metadata so RequireScope on a handler can see it.
//
// Unit tests cover each step:
//   middleware_test.go      — HTTPMiddleware validates and
//                             stamps into r.Context().
//   require_scope_test.go   — RequireScope reads from gRPC
//                             metadata.
//
// What's missing was the SEAM between them: does the
// gateway's annotateContext correctly read scopes from the
// HTTP context and stamp the MDKeyScopes metadata key?
// This file is that tripwire — if the seam silently
// disconnects in a future refactor, the integration test
// fails immediately rather than a tenant escalating in
// production.

func TestScopeClaim_EndToEndPropagation(t *testing.T) {
	tm, err := auth.NewTokenManager("propagation-test-secret-at-least-32-bytes-ok", "test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	mw := auth.NewAuthMiddleware(tm)

	wantScopes := []string{auth.ScopeContainersRead, auth.ScopeSecretsRead}
	tok, err := tm.GenerateAccessToken("alice", []string{"user"}, time.Hour, wantScopes...)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	// Capture what annotateContext produces when run with the
	// post-middleware request context. This is the contract the
	// gateway's gRPC client uses to forward to the server.
	var capturedMD metadata.MD
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMD = annotateContext(r.Context(), r)
		w.WriteHeader(http.StatusOK)
	})
	wrapped := mw.HTTPMiddleware(stub)

	req := httptest.NewRequest("GET", "/v1/containers", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if capturedMD == nil {
		t.Fatal("annotateContext returned no metadata")
	}

	// Username + roles always propagate.
	if got := capturedMD.Get(auth.MDKeyUsername); len(got) == 0 || got[0] != "alice" {
		t.Fatalf("username metadata = %v; want [alice]", got)
	}
	if got := capturedMD.Get(auth.MDKeyRoles); len(got) == 0 || got[0] != "user" {
		t.Fatalf("roles metadata = %v; want [user]", got)
	}

	// Scopes are the new bit. Must be present, comma-joined.
	scopesVals := capturedMD.Get(auth.MDKeyScopes)
	if len(scopesVals) != 1 {
		t.Fatalf("scopes metadata = %v; want exactly one entry", scopesVals)
	}
	if scopesVals[0] != strings.Join(wantScopes, ",") {
		t.Fatalf("scopes metadata = %q; want %q", scopesVals[0], strings.Join(wantScopes, ","))
	}

	// Reconstruct the gRPC-side context from the propagated
	// metadata and verify RequireScope reads it correctly —
	// this is the same code path the daemon's gRPC handlers
	// hit on every authenticated request.
	grpcCtx := metadata.NewIncomingContext(context.Background(), capturedMD)
	if err := auth.RequireScope(grpcCtx, auth.ScopeContainersRead); err != nil {
		t.Fatalf("RequireScope(containers:read) should pass; got %v", err)
	}
	if err := auth.RequireScope(grpcCtx, auth.ScopeSecretsRead); err != nil {
		t.Fatalf("RequireScope(secrets:read) should pass; got %v", err)
	}
	if err := auth.RequireScope(grpcCtx, auth.ScopeContainersWrite); err == nil {
		t.Fatal("RequireScope(containers:write) should fail — token doesn't grant it")
	}
}

func TestScopeClaim_AbsentClaimPropagatesAsAbsent(t *testing.T) {
	// Pre-1.7 tokens (no scopes claim) MUST keep working —
	// backwards compat is a security property. The metadata
	// MUST NOT carry a scopes entry, and RequireScope must
	// treat the absent claim as unrestricted.
	tm, _ := auth.NewTokenManager("propagation-test-secret-at-least-32-bytes-ok", "test")
	mw := auth.NewAuthMiddleware(tm)

	tok, _ := tm.GenerateToken("alice", []string{"user"}, time.Hour) // no scopes

	var capturedMD metadata.MD
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMD = annotateContext(r.Context(), r)
		w.WriteHeader(http.StatusOK)
	})
	wrapped := mw.HTTPMiddleware(stub)

	req := httptest.NewRequest("GET", "/v1/containers", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if got := capturedMD.Get(auth.MDKeyScopes); len(got) != 0 {
		t.Fatalf("legacy token should NOT propagate scopes metadata; got %v", got)
	}

	grpcCtx := metadata.NewIncomingContext(context.Background(), capturedMD)
	// Any scope passes because nil grants are unrestricted.
	if err := auth.RequireScope(grpcCtx, auth.ScopeContainersWrite); err != nil {
		t.Fatalf("legacy token should pass any scope check; got %v", err)
	}
}

func TestScopeClaim_RefreshTokenRejectedAtMiddleware(t *testing.T) {
	// Refresh tokens carry scopes but cannot authenticate to
	// the API surface (Phase 1.6). The middleware rejects
	// them with 401, so the gateway never sees the context —
	// no metadata is propagated, no scope check runs.
	tm, _ := auth.NewTokenManager("propagation-test-secret-at-least-32-bytes-ok", "test")
	mw := auth.NewAuthMiddleware(tm)

	refresh, _ := tm.GenerateRefreshToken("alice", []string{"user"}, time.Hour, auth.ScopeContainersWrite)

	called := false
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	wrapped := mw.HTTPMiddleware(stub)

	req := httptest.NewRequest("GET", "/v1/containers", nil)
	req.Header.Set("Authorization", "Bearer "+refresh)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("refresh token at API: status=%d, want 401", rec.Code)
	}
	if called {
		t.Fatal("inner handler must NOT run for a refresh token")
	}
}
