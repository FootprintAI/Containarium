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
