package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeRevocationStore is a small in-memory stub of
// auth.RevocationStore for the RPC-level tests in this file.
// (The Postgres-backed impl is exercised by the integration
// suite.)
type fakeRevocationStore struct {
	mu       sync.Mutex
	revoked  map[string]string // jti -> reason
	failNext bool
}

func newFakeRevocationStore() *fakeRevocationStore {
	return &fakeRevocationStore{revoked: map[string]string{}}
}

func (f *fakeRevocationStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.revoked[jti]
	return ok, nil
}

func (f *fakeRevocationStore) Revoke(_ context.Context, jti string, _ time.Time, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext {
		f.failNext = false
		return errors.New("simulated DB error")
	}
	if _, exists := f.revoked[jti]; !exists {
		f.revoked[jti] = reason
	}
	return nil
}

func (f *fakeRevocationStore) CleanupExpired(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (f *fakeRevocationStore) List(_ context.Context, _ auth.ListRevocationsParams) ([]auth.Revocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]auth.Revocation, 0, len(f.revoked))
	for jti, reason := range f.revoked {
		out = append(out, auth.Revocation{JTI: jti, Reason: reason})
	}
	return out, nil
}

func newTestTokensServer(t *testing.T, store auth.RevocationStore) *TokensServer {
	t.Helper()
	tm, err := auth.NewTokenManager("test-secret-must-be-at-least-32-bytes-long-ok", "test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	if store != nil {
		tm.SetRevocationStore(store)
	}
	return NewTokensServer(tm, store, time.Hour)
}

// --- authz gate ---

func TestRevokeToken_RejectsNonAdmin(t *testing.T) {
	srv := newTestTokensServer(t, newFakeRevocationStore())
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	_, err := srv.RevokeToken(ctx, &pb.RevokeTokenRequest{Jti: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin: got %v want PermissionDenied", err)
	}
}

// Phase 1.7b — RevokeToken now requires the tokens:write
// scope in addition to the admin role. Admin without the
// scope must still be rejected (scopes are orthogonal).
func TestRevokeToken_RejectsAdminMissingScope(t *testing.T) {
	srv := newTestTokensServer(t, newFakeRevocationStore())
	ctx := auth.ContextWithTestSubjectScopes(context.Background(),
		"ops", []string{auth.RoleAdmin},
		[]string{auth.ScopeContainersRead}, // no tokens:write
	)
	_, err := srv.RevokeToken(ctx, &pb.RevokeTokenRequest{Jti: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("admin without tokens:write: got %v want PermissionDenied", err)
	}
}

func TestRevokeToken_AdminWithScopePasses(t *testing.T) {
	store := newFakeRevocationStore()
	srv := newTestTokensServer(t, store)
	ctx := auth.ContextWithTestSubjectScopes(context.Background(),
		"ops", []string{auth.RoleAdmin},
		[]string{auth.ScopeTokensWrite},
	)
	resp, err := srv.RevokeToken(ctx, &pb.RevokeTokenRequest{Jti: "with-scope"})
	if err != nil {
		t.Fatalf("admin+tokens:write should pass; got %v", err)
	}
	if !resp.NewlyRevoked {
		t.Fatal("expected NewlyRevoked=true")
	}
}

func TestRevokeToken_RejectsNoSubject(t *testing.T) {
	srv := newTestTokensServer(t, newFakeRevocationStore())
	_, err := srv.RevokeToken(context.Background(), &pb.RevokeTokenRequest{Jti: "x"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing subject: got %v want Unauthenticated", err)
	}
}

// --- validation ---

func TestRevokeToken_RejectsEmptyJTI(t *testing.T) {
	srv := newTestTokensServer(t, newFakeRevocationStore())
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
	_, err := srv.RevokeToken(ctx, &pb.RevokeTokenRequest{Jti: ""})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty jti: got %v want InvalidArgument", err)
	}
}

func TestRevokeToken_RejectsMalformedExpiry(t *testing.T) {
	srv := newTestTokensServer(t, newFakeRevocationStore())
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
	_, err := srv.RevokeToken(ctx, &pb.RevokeTokenRequest{
		Jti:       "x",
		ExpiresAt: "not-a-date",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("malformed expires_at: got %v want InvalidArgument", err)
	}
}

func TestRevokeToken_UnavailableWhenStoreNil(t *testing.T) {
	srv := newTestTokensServer(t, nil)
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
	_, err := srv.RevokeToken(ctx, &pb.RevokeTokenRequest{Jti: "x"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("nil store: got %v want Unavailable", err)
	}
}

// --- happy path + idempotency ---

func TestRevokeToken_AdminSucceeds(t *testing.T) {
	store := newFakeRevocationStore()
	srv := newTestTokensServer(t, store)
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)

	resp, err := srv.RevokeToken(ctx, &pb.RevokeTokenRequest{
		Jti:    "test-jti-123",
		Reason: "leaked",
	})
	if err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if !resp.NewlyRevoked {
		t.Fatal("expected NewlyRevoked=true")
	}
	if reason, ok := store.revoked["test-jti-123"]; !ok {
		t.Fatal("jti not present in store")
	} else if reason != "leaked" {
		t.Fatalf("reason = %q, want %q", reason, "leaked")
	}
}

func TestRevokeToken_DefaultReason(t *testing.T) {
	store := newFakeRevocationStore()
	srv := newTestTokensServer(t, store)
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)

	_, err := srv.RevokeToken(ctx, &pb.RevokeTokenRequest{Jti: "x"})
	if err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if reason := store.revoked["x"]; reason != "operator_revoke" {
		t.Fatalf("default reason = %q, want %q", reason, "operator_revoke")
	}
}

func TestRevokeToken_Idempotent(t *testing.T) {
	store := newFakeRevocationStore()
	srv := newTestTokensServer(t, store)
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)

	for i := 0; i < 3; i++ {
		if _, err := srv.RevokeToken(ctx, &pb.RevokeTokenRequest{
			Jti:    "x",
			Reason: "first",
		}); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
	if reason := store.revoked["x"]; reason != "first" {
		t.Fatalf("reason = %q; want first (idempotency must preserve original reason)", reason)
	}
}

func TestRevokeToken_StoreErrorIsInternal(t *testing.T) {
	store := newFakeRevocationStore()
	store.failNext = true
	srv := newTestTokensServer(t, store)
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
	_, err := srv.RevokeToken(ctx, &pb.RevokeTokenRequest{Jti: "x"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("store error: got %v want Internal", err)
	}
}

func TestRevokeToken_AcceptsRFC3339Expiry(t *testing.T) {
	store := newFakeRevocationStore()
	srv := newTestTokensServer(t, store)
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)

	_, err := srv.RevokeToken(ctx, &pb.RevokeTokenRequest{
		Jti:       "x",
		ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("RFC3339 expiry should parse; got %v", err)
	}
}

// --- Phase 1.6 part B — RefreshToken RPC ---

func TestRefreshToken_RejectsEmpty(t *testing.T) {
	srv := newTestTokensServer(t, newFakeRevocationStore())
	_, err := srv.RefreshToken(context.Background(), &pb.RefreshTokenRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty refresh_token: got %v want InvalidArgument", err)
	}
}

func TestRefreshToken_RejectsAccessToken(t *testing.T) {
	// A request bearing an access token where a refresh is
	// expected must be rejected with Unauthenticated.
	srv := newTestTokensServer(t, newFakeRevocationStore())
	access, err := srv.tokenManager.GenerateAccessToken("alice", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	_, err = srv.RefreshToken(context.Background(), &pb.RefreshTokenRequest{RefreshToken: access})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("access at refresh: got %v want Unauthenticated", err)
	}
}

func TestRefreshToken_RejectsLegacyToken(t *testing.T) {
	srv := newTestTokensServer(t, newFakeRevocationStore())
	legacy, _ := srv.tokenManager.GenerateToken("alice", []string{"user"}, time.Hour)
	_, err := srv.RefreshToken(context.Background(), &pb.RefreshTokenRequest{RefreshToken: legacy})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("legacy at refresh: got %v want Unauthenticated", err)
	}
}

func TestRefreshToken_HappyPath_MintsNewPair(t *testing.T) {
	store := newFakeRevocationStore()
	srv := newTestTokensServer(t, store)
	refresh, _ := srv.tokenManager.GenerateRefreshToken("alice", []string{"user"}, time.Hour, auth.ScopeContainersRead)

	resp, err := srv.RefreshToken(context.Background(), &pb.RefreshTokenRequest{RefreshToken: refresh})
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Fatal("response should carry both new tokens")
	}
	if resp.AccessTokenExpiresAt == 0 || resp.RefreshTokenExpiresAt == 0 {
		t.Fatal("response should carry expiry timestamps")
	}

	// New access token validates as access; new refresh
	// validates as refresh. Scope passes through.
	ac, err := srv.tokenManager.ValidateAccessToken(resp.AccessToken)
	if err != nil {
		t.Fatalf("new access invalid: %v", err)
	}
	if ac.TokenType != auth.TokenTypeAccess {
		t.Fatalf("new access tt=%q", ac.TokenType)
	}
	if len(ac.Scopes) != 1 || ac.Scopes[0] != auth.ScopeContainersRead {
		t.Fatalf("new access scopes=%v; should pass through", ac.Scopes)
	}
	rc, err := srv.tokenManager.ValidateRefreshToken(resp.RefreshToken)
	if err != nil {
		t.Fatalf("new refresh invalid: %v", err)
	}
	if rc.TokenType != auth.TokenTypeRefresh {
		t.Fatalf("new refresh tt=%q", rc.TokenType)
	}
}

// --- ListRevokedTokens admin enumeration ---

func TestListRevokedTokens_RejectsNoSubject(t *testing.T) {
	srv := newTestTokensServer(t, newFakeRevocationStore())
	_, err := srv.ListRevokedTokens(context.Background(), &pb.ListRevokedTokensRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing subject: got %v want Unauthenticated", err)
	}
}

func TestListRevokedTokens_RejectsNonAdmin(t *testing.T) {
	srv := newTestTokensServer(t, newFakeRevocationStore())
	ctx := auth.ContextWithTestSubjectScopes(context.Background(),
		"alice", []string{"user"}, []string{auth.ScopeTokensWrite},
	)
	_, err := srv.ListRevokedTokens(ctx, &pb.ListRevokedTokensRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin: got %v want PermissionDenied", err)
	}
}

func TestListRevokedTokens_RejectsAdminMissingScope(t *testing.T) {
	srv := newTestTokensServer(t, newFakeRevocationStore())
	ctx := auth.ContextWithTestSubjectScopes(context.Background(),
		"ops", []string{auth.RoleAdmin}, []string{auth.ScopeContainersRead},
	)
	_, err := srv.ListRevokedTokens(ctx, &pb.ListRevokedTokensRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("admin without tokens:write: got %v want PermissionDenied", err)
	}
}

func TestListRevokedTokens_AdminWithScopeSucceeds(t *testing.T) {
	store := newFakeRevocationStore()
	_ = store.Revoke(context.Background(), "abc123", time.Now().Add(time.Hour), "test")
	srv := newTestTokensServer(t, store)
	ctx := auth.ContextWithTestSubjectScopes(context.Background(),
		"ops", []string{auth.RoleAdmin}, []string{auth.ScopeTokensWrite},
	)
	resp, err := srv.ListRevokedTokens(ctx, &pb.ListRevokedTokensRequest{})
	if err != nil {
		t.Fatalf("ListRevokedTokens: %v", err)
	}
	if len(resp.Revocations) != 1 {
		t.Fatalf("len(revocations) = %d, want 1", len(resp.Revocations))
	}
	if resp.Revocations[0].Jti != "abc123" {
		t.Fatalf("jti = %q, want %q", resp.Revocations[0].Jti, "abc123")
	}
}

func TestListRevokedTokens_UnavailableWhenStoreNil(t *testing.T) {
	srv := newTestTokensServer(t, nil)
	ctx := auth.ContextWithTestSubjectScopes(context.Background(),
		"ops", []string{auth.RoleAdmin}, []string{auth.ScopeTokensWrite},
	)
	_, err := srv.ListRevokedTokens(ctx, &pb.ListRevokedTokensRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("nil store: got %v want Unavailable", err)
	}
}

func TestRefreshToken_RotationRevokesPriorJTI(t *testing.T) {
	// Single-use semantics: after a successful exchange,
	// replaying the same refresh token must fail.
	store := newFakeRevocationStore()
	srv := newTestTokensServer(t, store)
	refresh, _ := srv.tokenManager.GenerateRefreshToken("alice", []string{"user"}, time.Hour)

	// First exchange succeeds.
	if _, err := srv.RefreshToken(context.Background(), &pb.RefreshTokenRequest{RefreshToken: refresh}); err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	// The prior jti is now revoked. Validate the old
	// refresh token through the same path — the
	// revocation list check inside ValidateRefreshToken's
	// chain trips and returns invalid.
	srv.tokenManager.SetRevocationStore(store)
	_, err := srv.RefreshToken(context.Background(), &pb.RefreshTokenRequest{RefreshToken: refresh})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("replay should be rejected; got %v", err)
	}
}
