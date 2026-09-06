package secrets

import (
	"context"
	"os"
	"testing"

	corecrypto "github.com/footprintai/containarium/pkg/core/secrets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration-style test against a real Postgres. Follows the same
// convention as internal/app/store_test.go: t.Skip in CI, runnable
// locally with:
//
//	docker run -d -p 5432:5432 \
//	  -e POSTGRES_PASSWORD=test \
//	  -e POSTGRES_DB=containarium \
//	  postgres:16-alpine
//
//	go test -run TestSecretsStore ./internal/secrets/ -v
//
// The crypto layer is fully unit-tested in pkg/core/secrets;
// this test exercises the SQL roundtrip + AAD binding through
// the full Store API.
func TestSecretsStore_Roundtrip(t *testing.T) {
	// Gated on the DSN rather than skipped unconditionally. It skipped for
	// everyone, everywhere, including the lane that was supposed to run it —
	// so the SQL roundtrip and AAD binding below had never executed (#1300).
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

	// 32-byte fixed key — only valid for tests; production uses
	// LoadOrCreateMasterKey from a 0400 file.
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

	// Clean slate for this test user.
	_, _ = pool.Exec(ctx, "DELETE FROM secrets WHERE username = $1", "store-test-user")

	// Set, then Get, then List, then rotation (Set again), then
	// Delete.
	meta, err := store.Set(ctx, "store-test-user", "OPENAI_API_KEY", "sk-v1", "")
	if err != nil {
		t.Fatalf("Set first: %v", err)
	}
	if meta.Version != 1 {
		t.Errorf("first version = %d, want 1", meta.Version)
	}

	gotMeta, gotValue, err := store.Get(ctx, "store-test-user", "OPENAI_API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotValue != "sk-v1" {
		t.Errorf("Get value = %q, want %q", gotValue, "sk-v1")
	}
	if gotMeta.Version != 1 {
		t.Errorf("Get version = %d, want 1", gotMeta.Version)
	}

	// Rotation: same (username, name), new value, version should bump.
	meta2, err := store.Set(ctx, "store-test-user", "OPENAI_API_KEY", "sk-v2", "")
	if err != nil {
		t.Fatalf("Set rotation: %v", err)
	}
	if meta2.Version != 2 {
		t.Errorf("rotation version = %d, want 2", meta2.Version)
	}

	// LoadAllForUser returns a map of every secret decrypted.
	all, err := store.LoadAllForUser(ctx, "store-test-user")
	if err != nil {
		t.Fatalf("LoadAllForUser: %v", err)
	}
	if all["OPENAI_API_KEY"] != "sk-v2" {
		t.Errorf("LoadAllForUser[OPENAI_API_KEY] = %q, want sk-v2", all["OPENAI_API_KEY"])
	}

	// List returns metadata only.
	list, err := store.List(ctx, "store-test-user")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("List len = %d, want 1", len(list))
	}

	// Delete + verify it's gone.
	if err := store.Delete(ctx, "store-test-user", "OPENAI_API_KEY"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := store.Get(ctx, "store-test-user", "OPENAI_API_KEY"); err != ErrNotFound {
		t.Errorf("Get after delete: err = %v, want ErrNotFound", err)
	}

	// Delete-after-delete should also return ErrNotFound.
	if err := store.Delete(ctx, "store-test-user", "OPENAI_API_KEY"); err != ErrNotFound {
		t.Errorf("double delete: err = %v, want ErrNotFound", err)
	}
}

// #1604 — env was the unspecified default: any process in the same
// container that can read /proc/<pid>/environ sees every secret, and Incus
// itself prints it in cleartext (`incus config show`). file closes both and
// is now what a caller gets without asking for it by name; env stays fully
// supported and selectable via an explicit delivery argument.
func TestSecretsStore_DeliveryDefaultsToFile(t *testing.T) {
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

	const user = "store-delivery-default-test-user"
	_, _ = pool.Exec(ctx, "DELETE FROM secrets WHERE username = $1", user)

	t.Run("unspecified delivery becomes file", func(t *testing.T) {
		meta, err := store.Set(ctx, user, "UNSPECIFIED_DELIVERY", "v1", "")
		if err != nil {
			t.Fatalf("Set: %v", err)
		}
		if meta.Delivery != DeliveryFile {
			t.Errorf("Delivery = %q, want %q (#1604's new default)", meta.Delivery, DeliveryFile)
		}
	})

	t.Run("explicit env is still honored, not upgraded to file", func(t *testing.T) {
		meta, err := store.Set(ctx, user, "EXPLICIT_ENV", "v1", DeliveryEnv)
		if err != nil {
			t.Fatalf("Set: %v", err)
		}
		if meta.Delivery != DeliveryEnv {
			t.Errorf("Delivery = %q, want %q — an explicit choice must not be overridden", meta.Delivery, DeliveryEnv)
		}
	})

	t.Run("a rotation with unspecified delivery keeps the row's existing mode, not the new default", func(t *testing.T) {
		// Set (env) then rotate the value without repeating the delivery
		// argument — the same shape a caller upgrading nothing but the
		// value would use. Silently flipping delivery on an unrelated
		// value rotation would be exactly the kind of surprise #1671
		// (issuer replacement) already burned this codebase on once.
		if _, err := store.Set(ctx, user, "ROTATED_ENV", "v1", DeliveryEnv); err != nil {
			t.Fatalf("initial Set: %v", err)
		}
		meta, err := store.Set(ctx, user, "ROTATED_ENV", "v2", "")
		if err != nil {
			t.Fatalf("rotation Set: %v", err)
		}
		if meta.Delivery != DeliveryEnv {
			t.Errorf("Delivery after rotation = %q, want %q preserved from the original Set", meta.Delivery, DeliveryEnv)
		}
	})
}

func TestSecretsStore_NilArgsRejected(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, corecrypto.MasterKeySize)
	cipher, _ := corecrypto.NewCipher(key)

	if _, err := NewStore(ctx, nil, cipher); err == nil {
		t.Error("NewStore should reject nil pool")
	}
	// nil cipher — needs a pool, so we can't actually call this
	// without a Postgres. The pool == nil path is the cheap one to
	// exercise; the cipher==nil path is symmetrical.
}
