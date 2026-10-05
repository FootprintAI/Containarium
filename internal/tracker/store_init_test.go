package tracker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Concurrent-init tests (#2061). Every other store test shares the DSN's
// default schema, which the first NewStore in the process already
// initialized — so none of them can exercise a genuine FIRST run. These
// tests create a uniquely named, empty schema per round and point every
// pool's search_path at it, so the tracker tables really do not exist yet
// when the inits race.

// freshSchema creates an empty schema on the test database and returns
// its name. Dropped (CASCADE) when the test ends.
func freshSchema(t *testing.T, ctx context.Context, dsn string) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("random schema suffix: %v", err)
	}
	schema := "tracker_init_" + hex.EncodeToString(b[:])
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+ident+" CASCADE")
		_ = admin.Close(context.Background())
	})
	return schema
}

// newPoolInSchema opens a pool whose connections resolve unqualified
// table names in schema, so Store.initSchema creates its tables there.
// One pool per NewStore mimics one daemon replica per init: the racing
// inits never share a connection.
func newPoolInSchema(t *testing.T, ctx context.Context, dsn, schema string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// concurrentInits runs n NewStore calls at once against schema, each on
// its own pool, and returns their errors in call order.
func concurrentInits(t *testing.T, ctx context.Context, dsn, schema string, n int) []error {
	t.Helper()
	pools := make([]*pgxpool.Pool, n)
	for i := range pools {
		pools[i] = newPoolInSchema(t, ctx, dsn, schema)
	}
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = NewStore(ctx, pools[i])
		}(i)
	}
	close(start)
	wg.Wait()
	return errs
}

// assertStoreUsable proves the schema the inits left behind is complete:
// a connection round-trips through the table the whole batch hangs off.
func assertStoreUsable(t *testing.T, ctx context.Context, dsn, schema string) {
	t.Helper()
	store, err := NewStore(ctx, newPoolInSchema(t, ctx, dsn, schema))
	if err != nil {
		t.Fatalf("NewStore after the race: %v", err)
	}
	if _, err := store.Set(ctx, Connection{Username: "init-race", Name: "default", Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB, Project: "o/r", CredentialSecret: "s"}); err != nil {
		t.Fatalf("Set after the race: %v", err)
	}
	if _, err := store.Get(ctx, "init-race", "default"); err != nil {
		t.Fatalf("Get after the race: %v", err)
	}
}

// TestNewStore_ConcurrentFirstRunInits (#2061): several daemon replicas
// starting against a brand-new tracker database must all initialize.
// Before the fix most of them failed with SQLSTATE 23505 on
// pg_type_typname_nsp_index: CREATE TABLE IF NOT EXISTS checks pg_class
// and then inserts the table's row type into pg_type, so two sessions
// that both pass the check collide on the catalog's unique index, and
// the whole implicit-transaction batch rolls back for the loser.
// Reviewer probe, reproduced: 6 concurrent inits, ~5 of 6 failed.
func TestNewStore_ConcurrentFirstRunInits(t *testing.T) {
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres (the store-integration lane does)")
	}
	ctx := context.Background()
	const inits, rounds = 8, 3
	for round := 0; round < rounds; round++ {
		schema := freshSchema(t, ctx, dsn)
		var failed int
		for i, err := range concurrentInits(t, ctx, dsn, schema, inits) {
			if err == nil {
				continue
			}
			failed++
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				t.Errorf("round %d init %d: SQLSTATE %s on %q: %v", round, i, pgErr.Code, pgErr.ConstraintName, err)
			} else {
				t.Errorf("round %d init %d: %v", round, i, err)
			}
		}
		if failed > 0 {
			t.Errorf("round %d: %d of %d concurrent first-run inits failed, want 0", round, failed, inits)
		}
		assertStoreUsable(t, ctx, dsn, schema)
	}
}

// legacyTrackerSchema is the tracker_connections table as first released
// (#1921 step 3 and #2024 later ALTERed columns onto it; every other
// table came after). Pre-creating it alone turns a round into the
// upgrade case: tables already present, newer columns and tables missing.
const legacyTrackerSchema = `
	CREATE TABLE tracker_connections (
		username          TEXT NOT NULL,
		name              TEXT NOT NULL,
		provider          TEXT NOT NULL CHECK (provider IN ('github', 'gitlab')),
		base_url          TEXT NOT NULL DEFAULT '',
		project           TEXT NOT NULL,
		credential_secret TEXT NOT NULL,
		created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY (username, name)
	);
`

// TestNewStore_ConcurrentUpgradeInits (#2061): the upgrade case the
// reviewer found already passing 120/120 — the ALTER TABLE ... ADD
// COLUMN IF NOT EXISTS ahead of the new CREATEs happened to serialize the
// inits. Pinned so the first-run fix keeps it passing rather than relying
// on that accident.
func TestNewStore_ConcurrentUpgradeInits(t *testing.T) {
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres (the store-integration lane does)")
	}
	ctx := context.Background()
	schema := freshSchema(t, ctx, dsn)
	if _, err := newPoolInSchema(t, ctx, dsn, schema).Exec(ctx, legacyTrackerSchema); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	const inits = 8
	for i, err := range concurrentInits(t, ctx, dsn, schema, inits) {
		if err != nil {
			t.Errorf("upgrade init %d: %v", i, err)
		}
	}
	assertStoreUsable(t, ctx, dsn, schema)
	// The upgrade really added what was missing.
	var n int
	if err := newPoolInSchema(t, ctx, dsn, schema).QueryRow(ctx, fmt.Sprintf(
		`SELECT count(*) FROM information_schema.columns WHERE table_schema = '%s' AND table_name = 'tracker_connections' AND column_name IN ('credential_expires_at', 'policy')`, schema)).Scan(&n); err != nil {
		t.Fatalf("inspect upgraded columns: %v", err)
	}
	if n != 2 {
		t.Errorf("upgraded columns present = %d, want 2", n)
	}
}
