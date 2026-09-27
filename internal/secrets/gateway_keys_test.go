package secrets

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/modelgateway"
	corecrypto "github.com/footprintai/containarium/pkg/core/secrets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The store is the model gateway's per-owner key source; the interface it has
// to satisfy is declared over there (narrow, local — modelgateway keeps no
// dependency on this package, exactly like RevocationChecker).
var _ modelgateway.KeyResolver = (*Store)(nil)

// TestGatewayKeyLocation pins where a per-owner provider key lives: the
// reserved path __gateway/<key_owner>/<provider>, split into the store's
// (username, name) pair. A '/' can never appear in a tenant username, so the
// reserved namespace is disjoint from every tenant's by construction rather
// than by a filter someone has to remember.
func TestGatewayKeyLocation(t *testing.T) {
	tests := []struct {
		name         string
		keyOwner     string
		provider     string
		wantUsername string
		wantSecret   string
		wantPath     string
		wantErr      bool
	}{
		{
			name: "org owner", keyOwner: "org:3f2b1c4d-0000-4000-8000-000000000001", provider: "acmeai",
			wantUsername: "__gateway/org:3f2b1c4d-0000-4000-8000-000000000001",
			wantSecret:   "ACMEAI",
			wantPath:     "__gateway/org:3f2b1c4d-0000-4000-8000-000000000001/acmeai",
		},
		{
			name: "user owner", keyOwner: "user:bob", provider: "gemini-openai",
			wantUsername: "__gateway/user:bob",
			wantSecret:   "GEMINI_OPENAI",
			wantPath:     "__gateway/user:bob/gemini-openai",
		},
		{name: "empty owner", keyOwner: "", provider: "acmeai", wantErr: true},
		{name: "owner with a slash", keyOwner: "org:a/b", provider: "acmeai", wantErr: true},
		{name: "owner with whitespace", keyOwner: "org:a b", provider: "acmeai", wantErr: true},
		{name: "owner with a newline", keyOwner: "org:a\nb", provider: "acmeai", wantErr: true},
		{name: "empty provider", keyOwner: "user:bob", provider: "", wantErr: true},
		{name: "provider with bad characters", keyOwner: "user:bob", provider: "acme/ai", wantErr: true},
		{name: "upper-case provider", keyOwner: "user:bob", provider: "ACMEAI", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			username, secretName, err := GatewayKeyLocation(tc.keyOwner, tc.provider)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("GatewayKeyLocation(%q, %q) = (%q, %q), want an error", tc.keyOwner, tc.provider, username, secretName)
				}
				return
			}
			if err != nil {
				t.Fatalf("GatewayKeyLocation(%q, %q): %v", tc.keyOwner, tc.provider, err)
			}
			if username != tc.wantUsername || secretName != tc.wantSecret {
				t.Errorf("= (%q, %q), want (%q, %q)", username, secretName, tc.wantUsername, tc.wantSecret)
			}
			// The rendered path is the one the design names, so a log line or
			// an audit row reads the same as the doc.
			if got := username + "/" + strings.ToLower(strings.ReplaceAll(secretName, "_", "-")); got != tc.wantPath {
				t.Errorf("rendered path = %q, want %q", got, tc.wantPath)
			}
			if !IsGatewayKeyNamespace(username) {
				t.Errorf("IsGatewayKeyNamespace(%q) = false", username)
			}
			// The secret name must be storable — the store's own name rule is
			// env-var-shaped, which is why the owner/provider pair cannot be
			// one literal name.
			if err := corecrypto.ValidateName(secretName); err != nil {
				t.Errorf("secret name %q is not storable: %v", secretName, err)
			}
		})
	}

	if IsGatewayKeyNamespace("alice") {
		t.Error("a plain tenant username was mistaken for the reserved namespace")
	}
}

// TestReservedNamespaceRefusedOnTenantAPI — the tenant-facing surface refuses
// the reserved namespace outright, so no RPC that forwards a caller-supplied
// username can read, list, overwrite, or delete a per-owner gateway key. The
// zero-value Store has no pool: reaching Postgres would panic, so returning an
// error proves the guard runs before any DB work.
func TestReservedNamespaceRefusedOnTenantAPI(t *testing.T) {
	s := &Store{}
	ctx := context.Background()
	const reserved = "__gateway/org:acme"

	if _, err := s.Set(ctx, reserved, "ACMEAI", "k", DeliveryBroker); !errors.Is(err, ErrReservedNamespace) {
		t.Errorf("Set on the reserved namespace = %v, want ErrReservedNamespace", err)
	}
	if _, _, err := s.Get(ctx, reserved, "ACMEAI"); !errors.Is(err, ErrReservedNamespace) {
		t.Errorf("Get on the reserved namespace = %v, want ErrReservedNamespace", err)
	}
	if _, err := s.List(ctx, reserved); !errors.Is(err, ErrReservedNamespace) {
		t.Errorf("List on the reserved namespace = %v, want ErrReservedNamespace", err)
	}
	if err := s.Delete(ctx, reserved, "ACMEAI"); !errors.Is(err, ErrReservedNamespace) {
		t.Errorf("Delete on the reserved namespace = %v, want ErrReservedNamespace", err)
	}
	if _, err := s.LoadAllForUserWithDelivery(ctx, reserved); !errors.Is(err, ErrReservedNamespace) {
		t.Errorf("LoadAllForUserWithDelivery on the reserved namespace = %v, want ErrReservedNamespace", err)
	}
	if _, err := s.BrokerCredential(ctx, reserved, "ACMEAI"); !errors.Is(err, ErrReservedNamespace) {
		t.Errorf("BrokerCredential on the reserved namespace = %v, want ErrReservedNamespace", err)
	}
}

// TestGatewayProviderKey_Roundtrip is the store-integration half: a per-owner
// key set, read back, rotated and deleted, while the owning tenant's own
// secret listing and delivery load never see it.
//
// Gated on CONTAINARIUM_TEST_DSN, like TestSecretsStore_Roundtrip — the
// store-integration lane sets it.
func TestGatewayProviderKey_Roundtrip(t *testing.T) {
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres (the store-integration lane does)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	defer pool.Close()

	key := make([]byte, corecrypto.MasterKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	cipher, err := corecrypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	store, err := NewStore(ctx, pool, cipher)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	const owner = "user:gwkey-test-user"
	const tenant = "gwkey-test-user"
	_, _ = pool.Exec(ctx, "DELETE FROM secrets WHERE username = $1 OR username = $2", "__gateway/"+owner, tenant)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM secrets WHERE username = $1 OR username = $2", "__gateway/"+owner, tenant)
	})

	if _, ok := store.KeyFor(ctx, owner, "acmeai"); ok {
		t.Fatal("KeyFor reported a key before one was set")
	}
	if err := store.SetGatewayProviderKey(ctx, owner, "acmeai", "REAL-KEY-1"); err != nil {
		t.Fatalf("SetGatewayProviderKey: %v", err)
	}
	got, ok := store.KeyFor(ctx, owner, "acmeai")
	if !ok || got != "REAL-KEY-1" {
		t.Fatalf("KeyFor = (%q, %t), want (REAL-KEY-1, true)", got, ok)
	}
	// Rotation replaces, never duplicates.
	if err := store.SetGatewayProviderKey(ctx, owner, "acmeai", "REAL-KEY-2"); err != nil {
		t.Fatalf("SetGatewayProviderKey (rotate): %v", err)
	}
	if got, ok := store.KeyFor(ctx, owner, "acmeai"); !ok || got != "REAL-KEY-2" {
		t.Fatalf("after rotation KeyFor = (%q, %t), want (REAL-KEY-2, true)", got, ok)
	}

	// A different provider for the same owner, and a different owner, are
	// separate rows — no cross-talk.
	if _, ok := store.KeyFor(ctx, owner, "openai"); ok {
		t.Error("a key set for one provider answered for another")
	}
	if _, ok := store.KeyFor(ctx, "user:someone-else", "acmeai"); ok {
		t.Error("a key set for one owner answered for another")
	}

	// The tenant whose username is the owner's suffix sees nothing of it.
	if _, err := store.Set(ctx, tenant, "OWN_SECRET", "mine", DeliveryFile); err != nil {
		t.Fatalf("Set tenant secret: %v", err)
	}
	metas, err := store.List(ctx, tenant)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, m := range metas {
		if m.Name != "OWN_SECRET" {
			t.Errorf("tenant listing leaked %q", m.Name)
		}
	}
	loaded, err := store.LoadAllForUserWithDelivery(ctx, tenant)
	if err != nil {
		t.Fatalf("LoadAllForUserWithDelivery: %v", err)
	}
	if _, bad := loaded["ACMEAI"]; bad {
		t.Error("a per-owner gateway key reached a box delivery path")
	}

	if err := store.DeleteGatewayProviderKey(ctx, owner, "acmeai"); err != nil {
		t.Fatalf("DeleteGatewayProviderKey: %v", err)
	}
	if _, ok := store.KeyFor(ctx, owner, "acmeai"); ok {
		t.Fatal("KeyFor still reports a key after delete")
	}
	if err := store.DeleteGatewayProviderKey(ctx, owner, "acmeai"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v, want ErrNotFound", err)
	}
}
