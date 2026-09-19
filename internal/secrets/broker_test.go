package secrets

import (
	"context"
	"errors"
	"os"
	"testing"

	corecrypto "github.com/footprintai/containarium/pkg/core/secrets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration-style tests against a real Postgres, same convention as
// TestSecretsStore_Roundtrip (t.Skip in CI-without-DSN, runnable locally
// with CONTAINARIUM_TEST_DSN set — see store_test.go's docker run
// command). Exercises the broker-only delivery mode end to end: the
// SQL-level exclusion in LoadAllForUserWithDelivery, Get's write-only
// gate, BrokerCredential's read path, the one-way mode-change guard, and
// that a KEK rewrap still reaches broker rows.

func newBrokerTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres (the store-integration lane does)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	t.Cleanup(pool.Close)

	key := make([]byte, corecrypto.MasterKeySize)
	for i := range key {
		key[i] = byte(i + 7)
	}
	cph, err := corecrypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	store, err := NewStore(ctx, pool, cph)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store, ctx
}

func TestGet_BrokerRow_ReturnsErrBrokerOnly(t *testing.T) {
	store, ctx := newBrokerTestStore(t)
	const user = "broker-test-get"
	_, _ = store.pool.Exec(ctx, "DELETE FROM secrets WHERE username = $1", user)

	if _, err := store.Set(ctx, user, "GH_TOKEN", "ghp_secret", DeliveryBroker); err != nil {
		t.Fatalf("Set: %v", err)
	}

	meta, value, err := store.Get(ctx, user, "GH_TOKEN")
	if !errors.Is(err, ErrBrokerOnly) {
		t.Fatalf("Get err = %v, want ErrBrokerOnly", err)
	}
	if value != "" {
		t.Errorf("Get value = %q, want empty", value)
	}
	if meta == nil || meta.Delivery != DeliveryBroker {
		t.Errorf("Get meta = %+v, want non-nil with Delivery=%q", meta, DeliveryBroker)
	}
}

func TestBrokerCredential_ReturnsValue_OnlyForBrokerRows(t *testing.T) {
	store, ctx := newBrokerTestStore(t)
	const user = "broker-test-cred"
	_, _ = store.pool.Exec(ctx, "DELETE FROM secrets WHERE username = $1", user)

	if _, err := store.Set(ctx, user, "GH_TOKEN", "ghp_secret", DeliveryBroker); err != nil {
		t.Fatalf("Set broker: %v", err)
	}
	if _, err := store.Set(ctx, user, "OPENAI_KEY", "sk-live", DeliveryEnv); err != nil {
		t.Fatalf("Set env: %v", err)
	}

	got, err := store.BrokerCredential(ctx, user, "GH_TOKEN")
	if err != nil {
		t.Fatalf("BrokerCredential(broker row): %v", err)
	}
	if got != "ghp_secret" {
		t.Errorf("BrokerCredential = %q, want %q", got, "ghp_secret")
	}

	if _, err := store.BrokerCredential(ctx, user, "OPENAI_KEY"); !errors.Is(err, ErrNotBrokerOnly) {
		t.Fatalf("BrokerCredential(env row) err = %v, want ErrNotBrokerOnly", err)
	}
}

func TestSet_BrokerToDeliveringMode_Rejected(t *testing.T) {
	store, ctx := newBrokerTestStore(t)
	const user = "broker-test-immutable"
	_, _ = store.pool.Exec(ctx, "DELETE FROM secrets WHERE username = $1", user)

	if _, err := store.Set(ctx, user, "GH_TOKEN", "ghp_secret", DeliveryBroker); err != nil {
		t.Fatalf("Set broker: %v", err)
	}

	if _, err := store.Set(ctx, user, "GH_TOKEN", "ghp_new", DeliveryEnv); !errors.Is(err, ErrBrokerModeImmutable) {
		t.Fatalf("Set to env err = %v, want ErrBrokerModeImmutable", err)
	}
	if _, err := store.Set(ctx, user, "GH_TOKEN", "ghp_new", DeliveryFile); !errors.Is(err, ErrBrokerModeImmutable) {
		t.Fatalf("Set to file err = %v, want ErrBrokerModeImmutable", err)
	}

	// Re-setting broker-only again (rotation) stays allowed.
	if _, err := store.Set(ctx, user, "GH_TOKEN", "ghp_rotated", DeliveryBroker); err != nil {
		t.Fatalf("Set broker again (rotation): %v", err)
	}
	got, err := store.BrokerCredential(ctx, user, "GH_TOKEN")
	if err != nil {
		t.Fatalf("BrokerCredential after rotation: %v", err)
	}
	if got != "ghp_rotated" {
		t.Errorf("BrokerCredential after rotation = %q, want %q", got, "ghp_rotated")
	}

	// An unspecified delivery on rotation preserves broker-only (matches
	// the existing "empty explicit preserves current mode" rule) rather
	// than tripping the immutability guard.
	if _, err := store.Set(ctx, user, "GH_TOKEN", "ghp_again", ""); err != nil {
		t.Fatalf("Set with unspecified delivery on a broker row: %v", err)
	}
}

func TestLoadAllForUserWithDelivery_ExcludesBrokerRows(t *testing.T) {
	store, ctx := newBrokerTestStore(t)
	const user = "broker-test-load"
	_, _ = store.pool.Exec(ctx, "DELETE FROM secrets WHERE username = $1", user)

	if _, err := store.Set(ctx, user, "GH_TOKEN", "ghp_secret", DeliveryBroker); err != nil {
		t.Fatalf("Set broker: %v", err)
	}
	if _, err := store.Set(ctx, user, "OPENAI_KEY", "sk-live", DeliveryEnv); err != nil {
		t.Fatalf("Set env: %v", err)
	}

	full, err := store.LoadAllForUserWithDelivery(ctx, user)
	if err != nil {
		t.Fatalf("LoadAllForUserWithDelivery: %v", err)
	}
	if _, ok := full["GH_TOKEN"]; ok {
		t.Errorf("broker row GH_TOKEN present in LoadAllForUserWithDelivery, want excluded")
	}
	if v, ok := full["OPENAI_KEY"]; !ok || v.Value != "sk-live" {
		t.Errorf("env row OPENAI_KEY = %+v, ok=%v, want sk-live present", v, ok)
	}

	// LoadAllForUser delegates to the above — same exclusion applies.
	flat, err := store.LoadAllForUser(ctx, user)
	if err != nil {
		t.Fatalf("LoadAllForUser: %v", err)
	}
	if _, ok := flat["GH_TOKEN"]; ok {
		t.Errorf("broker row GH_TOKEN present in LoadAllForUser, want excluded")
	}

	// List (metadata only) still shows the broker row with its mode —
	// only decrypt-and-deliver paths exclude it.
	all, err := store.List(ctx, user)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, m := range all {
		if m.Name == "GH_TOKEN" {
			found = true
			if m.Delivery != DeliveryBroker {
				t.Errorf("List GH_TOKEN delivery = %q, want %q", m.Delivery, DeliveryBroker)
			}
		}
	}
	if !found {
		t.Error("List did not include the broker row at all — metadata should still be visible")
	}
}

func TestRewrapTenant_IncludesBrokerRows(t *testing.T) {
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
		key[i] = byte(i + 11)
	}
	cph, err := corecrypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	built := map[string]int{}
	store, err := NewStore(ctx, pool, cph,
		WithKMS(&fakeTenantKMS{kekID: "shared"}),
		WithTenantKMSFactory(newFakeFactory(t, built)),
	)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	const user = "broker-test-rewrap"
	_, _ = pool.Exec(ctx, "DELETE FROM secrets WHERE username = $1", user)

	if _, err := store.Set(ctx, user, "GH_TOKEN", "ghp_secret", DeliveryBroker); err != nil {
		t.Fatalf("Set broker: %v", err)
	}
	metaBefore, err := store.BrokerCredential(ctx, user, "GH_TOKEN")
	if err != nil {
		t.Fatalf("BrokerCredential before rewrap: %v", err)
	}

	if err := store.SetTenantKMSKey(ctx, user, "tenant-key-1"); err != nil {
		t.Fatalf("SetTenantKMSKey (triggers rewrapTenant): %v", err)
	}

	got, err := store.BrokerCredential(ctx, user, "GH_TOKEN")
	if err != nil {
		t.Fatalf("BrokerCredential after rewrap: %v", err)
	}
	if got != metaBefore {
		t.Errorf("BrokerCredential after rewrap = %q, want unchanged %q", got, metaBefore)
	}
	if built["tenant-key-1"] == 0 {
		t.Error("tenant KMS factory never invoked for tenant-key-1 — rewrap did not run under the new key")
	}
}
