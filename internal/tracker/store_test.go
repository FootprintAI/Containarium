package tracker

import (
	"context"
	"errors"
	"os"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration-style tests against a real Postgres, same convention as
// internal/secrets' store tests: t.Skip in CI-without-DSN, runnable
// locally with CONTAINARIUM_TEST_DSN set (see internal/secrets/store_test.go
// for the docker run command), and executed for real by the
// store-integration CI lane.

func newTrackerTestStore(t *testing.T) (*Store, context.Context) {
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
	store, err := NewStore(ctx, pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store, ctx
}

func TestTrackerStore_CRUDRoundTrip(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-crud"
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_connections WHERE username = $1", user)

	created, err := store.Set(ctx, Connection{
		Username:         user,
		Name:             "default",
		Provider:         pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:          "acme/widgets",
		CredentialSecret: "GH_TOKEN",
	})
	if err != nil {
		t.Fatalf("Set (create): %v", err)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Errorf("Set (create) left timestamps zero: %+v", created)
	}

	got, err := store.Get(ctx, user, "default")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Provider != pb.TrackerProvider_TRACKER_PROVIDER_GITHUB || got.Project != "acme/widgets" || got.CredentialSecret != "GH_TOKEN" {
		t.Errorf("Get = %+v, want provider=GITHUB project=acme/widgets credential_secret=GH_TOKEN", got)
	}

	// Update (same username+name, different fields) — Set is an upsert.
	updated, err := store.Set(ctx, Connection{
		Username:         user,
		Name:             "default",
		Provider:         pb.TrackerProvider_TRACKER_PROVIDER_GITLAB,
		BaseURL:          "https://gitlab.example.com",
		Project:          "acme/widgets-v2",
		CredentialSecret: "GL_TOKEN",
	})
	if err != nil {
		t.Fatalf("Set (update): %v", err)
	}
	if updated.Provider != pb.TrackerProvider_TRACKER_PROVIDER_GITLAB || updated.Project != "acme/widgets-v2" {
		t.Errorf("Set (update) = %+v, want provider=GITLAB project=acme/widgets-v2", updated)
	}
	if !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("Set (update) CreatedAt = %v, want unchanged %v", updated.CreatedAt, created.CreatedAt)
	}

	list, err := store.List(ctx, user)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Name != "default" {
		t.Errorf("List = %+v, want exactly one connection named default", list)
	}

	if err := store.Delete(ctx, user, "default"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, user, "default"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete err = %v, want ErrNotFound", err)
	}
	if err := store.Delete(ctx, user, "default"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete (already gone) err = %v, want ErrNotFound", err)
	}
}

func TestGet_OtherTenantsConnection_NotFound(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const owner = "tracker-store-tenant-owner"
	const other = "tracker-store-tenant-other"
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_connections WHERE username IN ($1, $2)", owner, other)

	if _, err := store.Set(ctx, Connection{
		Username: owner, Name: "default",
		Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:  "acme/widgets", CredentialSecret: "GH_TOKEN",
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if _, err := store.Get(ctx, other, "default"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get by a different tenant err = %v, want ErrNotFound", err)
	}
	otherList, err := store.List(ctx, other)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(otherList) != 0 {
		t.Errorf("List(%q) = %+v, want empty (owned by %q)", other, otherList, owner)
	}
}

func TestTrackerStore_UnknownProviderString_RejectedByCheckConstraint(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-bad-provider"
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_connections WHERE username = $1", user)

	// providerToString already refuses to send anything but "github" /
	// "gitlab" through Set — this test proves the CHECK constraint itself
	// is a real backstop, by inserting a bogus value directly.
	_, err := store.pool.Exec(ctx,
		`INSERT INTO tracker_connections (username, name, provider, project, credential_secret) VALUES ($1, $2, $3, $4, $5)`,
		user, "default", "bitbucket", "acme/widgets", "BB_TOKEN")
	if err == nil {
		t.Fatal("insert with provider='bitbucket' succeeded, want a CHECK constraint violation")
	}
}

func TestSet_UnspecifiedProvider_Rejected(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-unspecified-provider"
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_connections WHERE username = $1", user)

	_, err := store.Set(ctx, Connection{
		Username: user, Name: "default",
		Project: "acme/widgets", CredentialSecret: "GH_TOKEN",
		// Provider left at its zero value (UNSPECIFIED).
	})
	if err == nil {
		t.Fatal("Set with UNSPECIFIED provider succeeded, want an error")
	}
}
