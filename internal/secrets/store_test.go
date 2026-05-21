package secrets

import (
	"context"
	"testing"

	corecrypto "github.com/footprintai/containarium/pkg/core/secrets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration-style test against a real Postgres. Follows the same
// convention as internal/app/store_test.go: t.Skip in CI, runnable
// locally with:
//
//   docker run -d -p 5432:5432 \
//     -e POSTGRES_PASSWORD=test \
//     -e POSTGRES_DB=containarium \
//     postgres:16-alpine
//
//   go test -run TestSecretsStore ./internal/secrets/ -v
//
// The crypto layer is fully unit-tested in pkg/core/secrets;
// this test exercises the SQL roundtrip + AAD binding through
// the full Store API.
func TestSecretsStore_Roundtrip(t *testing.T) {
	t.Skip("requires Postgres at localhost:5432 — see comment for run instructions")

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, "postgres://containarium:test@localhost:5432/containarium?sslmode=disable")
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
