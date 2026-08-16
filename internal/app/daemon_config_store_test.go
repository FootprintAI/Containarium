package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Postgres coverage for the daemon config store (#1300).
//
// This store exists so the daemon can self-bootstrap after its VM is
// recreated: it is where the alert webhook secret and the metrics-export
// config live between restarts. A bug here is not visible at write time —
// the daemon comes back up and is quietly missing the configuration it was
// running with, which is the failure mode #1080 already burned this project
// on once.
//
// It had no test of any kind. Gated on the DSN like the rest of this
// package, not skipped unconditionally: the store-integration lane sets it
// and asserts these ran.

func newDaemonConfigStoreForTest(t *testing.T) (*DaemonConfigStore, string) {
	t.Helper()
	store, err := NewDaemonConfigStore(context.Background(), routeTestPool(t))
	if err != nil {
		t.Fatalf("NewDaemonConfigStore: %v", err)
	}
	// Unique per test so repeated or parallel runs cannot collide on the
	// primary key, and so cleanup can be scoped to this test's rows.
	prefix := fmt.Sprintf("test.%s.%d.", strings.ReplaceAll(t.Name(), "/", "_"), os.Getpid())
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(),
			"DELETE FROM daemon_config WHERE key LIKE $1", prefix+"%")
	})
	return store, prefix
}

// Set has to be an upsert. The daemon writes the same keys on every start,
// so a plain INSERT would fail on the primary key the second time the daemon
// ever booted — and the value it failed to write is the one it needs after
// the NEXT restart.
func TestDaemonConfigStore_SetIsAnUpsert(t *testing.T) {
	ctx := context.Background()
	store, prefix := newDaemonConfigStoreForTest(t)
	key := prefix + "webhook_secret"

	if err := store.Set(ctx, key, "first"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := store.Set(ctx, key, "second"); err != nil {
		t.Fatalf("re-Set the same key: %v — a non-upsert fails on the primary key, and the "+
			"daemon rewrites these on every start", err)
	}

	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "second" {
		t.Errorf("value = %q, want the updated %q", got, "second")
	}
}

// A missing key returns an ERROR, not ("", nil).
//
// The doc comment on Get says "Returns empty string if not found", and that
// is wrong — it returns pgx.ErrNoRows. Worth pinning rather than quietly
// fixing the comment, because the difference decides how a caller is written:
// the one production reader (metrics_export_server.go) does
// `if raw, err := Get(...); err == nil && raw != ""`, which is correct against
// the real behaviour and would silently swallow genuine database errors if it
// had been written against the comment instead.
func TestDaemonConfigStore_GetReportsAMissingKeyAsAnError(t *testing.T) {
	ctx := context.Background()
	store, prefix := newDaemonConfigStoreForTest(t)

	got, err := store.Get(ctx, prefix+"definitely-absent")
	if err == nil {
		t.Fatalf("Get on an absent key returned (%q, nil) — a caller cannot then tell 'never "+
			"configured' from 'configured as the empty string' from 'the database is down', and "+
			"the daemon would boot with defaults believing that was the stored config", got)
	}
	if !errors.Is(err, ErrDaemonConfigNotFound) {
		t.Errorf("err = %v, want ErrDaemonConfigNotFound — matching on the message instead is "+
			"what the sentinel exists to avoid", err)
	}
	// The underlying pgx error stays reachable, so existing callers that
	// match on it are not broken by the sentinel.
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("err = %v, want pgx.ErrNoRows to remain matchable underneath", err)
	}
	if got != "" {
		t.Errorf("value = %q alongside the error, want empty", got)
	}
}

// An empty stored value is a real value, distinguishable from absence. This
// is the case the sentinel buys: without it, "" and not-found are the same
// answer.
func TestDaemonConfigStore_AnEmptyValueIsNotAbsence(t *testing.T) {
	ctx := context.Background()
	store, prefix := newDaemonConfigStoreForTest(t)
	key := prefix + "deliberately_empty"

	if err := store.Set(ctx, key, ""); err != nil {
		t.Fatalf("Set to empty: %v", err)
	}
	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get of a deliberately-empty value returned an error (%v) — the daemon cannot "+
			"then store 'this is switched off' as distinct from 'never set'", err)
	}
	if got != "" {
		t.Errorf("value = %q, want the empty string that was stored", got)
	}
}

func TestDaemonConfigStore_GetAllReturnsWhatWasWritten(t *testing.T) {
	ctx := context.Background()
	store, prefix := newDaemonConfigStoreForTest(t)

	want := map[string]string{
		prefix + "a": "1",
		prefix + "b": "2",
		prefix + "c": "3",
	}
	if err := store.SetAll(ctx, want); err != nil {
		t.Fatalf("SetAll: %v", err)
	}

	all, err := store.GetAll(ctx)
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	for k, v := range want {
		if all[k] != v {
			t.Errorf("GetAll()[%q] = %q, want %q — this is the map the daemon rehydrates from "+
				"after a VM recreation, so a missing pair is config silently lost", k, all[k], v)
		}
	}
}

// SetAll must upsert too, for the same reason Set does.
func TestDaemonConfigStore_SetAllOverwritesExistingKeys(t *testing.T) {
	ctx := context.Background()
	store, prefix := newDaemonConfigStoreForTest(t)
	key := prefix + "rewritten"

	if err := store.Set(ctx, key, "before"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := store.SetAll(ctx, map[string]string{key: "after"}); err != nil {
		t.Fatalf("SetAll over an existing key: %v", err)
	}

	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "after" {
		t.Errorf("value = %q, want %q", got, "after")
	}
}

// SetAll is a transaction, and the rollback is the reason it is one.
//
// A partial batch is worse than a failed one: the daemon would come back with
// half of one configuration and half of another, and nothing would report it.
// The failure is induced with a NUL byte, which PostgreSQL rejects in TEXT —
// a deterministic mid-statement error that needs no fault injection.
//
// Map iteration order is random, so which key hits the bad row first varies.
// With many good keys and one bad one, the run that writes nothing before
// failing is rare; every run still asserts the same thing, and the assertion
// holds either way.
func TestDaemonConfigStore_SetAllRollsBackAPartialBatch(t *testing.T) {
	ctx := context.Background()
	store, prefix := newDaemonConfigStoreForTest(t)

	batch := map[string]string{}
	for i := 0; i < 20; i++ {
		key := fmt.Sprintf("%sgood%02d", prefix, i)
		if err := store.Set(ctx, key, "before"); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
		batch[key] = "after"
	}
	batch[prefix+"poison"] = "bad\x00value" // PostgreSQL rejects NUL in TEXT

	if err := store.SetAll(ctx, batch); err == nil {
		t.Fatal("SetAll accepted a value PostgreSQL cannot store — the induced failure did not " +
			"happen, so this test proves nothing about rollback")
	}

	after, err := store.GetAll(ctx)
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	for key := range batch {
		if key == prefix+"poison" {
			if _, present := after[key]; present {
				t.Errorf("the poison key %q was committed despite the batch failing", key)
			}
			continue
		}
		if after[key] != "before" {
			t.Errorf("%q = %q after a failed batch, want the original %q — the transaction did "+
				"not roll back, so the daemon now holds half of one configuration and half of "+
				"another with nothing reporting it", key, after[key], "before")
		}
	}
}

// The schema initialiser runs on every daemon start, so it has to be safe to
// run against a database that already has the table.
func TestDaemonConfigStore_SchemaInitIsRepeatable(t *testing.T) {
	ctx := context.Background()
	store, prefix := newDaemonConfigStoreForTest(t)
	key := prefix + "survivor"

	if err := store.Set(ctx, key, "value"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// A second store over the same database, as a restart produces.
	if _, err := NewDaemonConfigStore(ctx, store.pool); err != nil {
		t.Fatalf("re-initialising the schema failed: %v — the daemon would not start twice", err)
	}

	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get after re-init: %v", err)
	}
	if got != "value" {
		t.Errorf("value = %q after re-initialising the schema, want %q — a re-init that dropped "+
			"data would erase the config the daemon restarted to recover", got, "value")
	}
}
