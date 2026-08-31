package server

import (
	"context"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/secrets"
	corecrypto "github.com/footprintai/containarium/pkg/core/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/jackc/pgx/v5/pgxpool"
)

// #1630 — SetTenantKMSKey's authz is deliberately NOT
// AuthorizeSecretTenant's self-access-exempt shape: admin role +
// explicit secrets:write scope are required unconditionally, even when
// the caller's own subject equals the requested username. These tests
// pin that directly, mirroring internal/auth/secrets_authz_test.go's
// context-construction convention (metadata.NewIncomingContext with the
// same MD keys) since SetTenantKMSKey doesn't route through
// AuthorizeSecretTenant at all.

func kmsKeyTestCtx(username, roles, scopes string) context.Context {
	pairs := []string{auth.MDKeyUsername, username, auth.MDKeyRoles, roles}
	if scopes != "" {
		pairs = append(pairs, auth.MDKeyScopes, scopes)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(pairs...))
}

func TestSetTenantKMSKey_NoAuthContext(t *testing.T) {
	s := &ContainerServer{secretsStore: mustTestSecretsStore(t)}
	_, err := s.SetTenantKMSKey(context.Background(),
		&pb.SetTenantKMSKeyRequest{Username: "alice", KekResourceName: "k"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestSetTenantKMSKey_NonAdminDenied(t *testing.T) {
	s := &ContainerServer{secretsStore: mustTestSecretsStore(t)}
	ctx := kmsKeyTestCtx("alice", "member", "secrets:write")
	_, err := s.SetTenantKMSKey(ctx, &pb.SetTenantKMSKeyRequest{Username: "alice", KekResourceName: "k"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestSetTenantKMSKey_AdminWithoutExplicitScopeDenied(t *testing.T) {
	// The composition this RPC exists to avoid: an unscoped admin
	// token must NOT be enough, even for changing its own tenant's
	// key — this is a privileged operation with no self-access
	// exception (see the handler's doc comment).
	s := &ContainerServer{secretsStore: mustTestSecretsStore(t)}
	ctx := kmsKeyTestCtx("cloud-daemon", "admin", "")
	_, err := s.SetTenantKMSKey(ctx, &pb.SetTenantKMSKeyRequest{Username: "cloud-daemon", KekResourceName: "k"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestSetTenantKMSKey_AdminWithExplicitScopeAllowed(t *testing.T) {
	s := &ContainerServer{secretsStore: mustTestSecretsStore(t)}
	ctx := kmsKeyTestCtx("cloud-daemon", "admin", "secrets:write")

	// No tenant factory wired on this store (no CONTAINARIUM_KMS_BACKEND=gcp
	// in this test process) — the authz gate must be satisfied and the
	// request must reach the store, which then reports the real
	// FailedPrecondition rather than PermissionDenied.
	_, err := s.SetTenantKMSKey(ctx, &pb.SetTenantKMSKeyRequest{
		Username: "authz-ok-user", KekResourceName: "projects/p/locations/l/keyRings/r/cryptoKeys/k",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (authz passed, store correctly refused — no gcp backend configured)", status.Code(err))
	}
}

func TestSetTenantKMSKey_StoreNotConfigured(t *testing.T) {
	s := &ContainerServer{} // secretsStore left nil — --standalone daemon
	ctx := kmsKeyTestCtx("cloud-daemon", "admin", "secrets:write")
	_, err := s.SetTenantKMSKey(ctx, &pb.SetTenantKMSKeyRequest{Username: "alice", KekResourceName: "k"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

func TestSetTenantKMSKey_RequiresUsername(t *testing.T) {
	s := &ContainerServer{secretsStore: mustTestSecretsStore(t)}
	ctx := kmsKeyTestCtx("cloud-daemon", "admin", "secrets:write")
	_, err := s.SetTenantKMSKey(ctx, &pb.SetTenantKMSKeyRequest{Username: "", KekResourceName: "k"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

// mustTestSecretsStore returns a real Store against CONTAINARIUM_TEST_DSN,
// skipping the test if it isn't set — same convention as
// internal/secrets' own Postgres-gated tests. secrets.Store is a
// concrete struct (correctly — the RPCs are the interface boundary),
// so there's no lighter-weight fake to construct here; every test in
// this file needs a real Store to get past the server's nil-store
// check regardless of which code path it's actually exercising.
func mustTestSecretsStore(t *testing.T) *secrets.Store {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	key := make([]byte, corecrypto.MasterKeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cph, err := corecrypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	store, err := secrets.NewStore(ctx, pool, cph)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}
