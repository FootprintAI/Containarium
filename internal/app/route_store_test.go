package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres coverage for the route store (#1300).
//
// Routes are the data plane: each record maps a public domain to a container
// IP and port, and the gateway serves traffic from them. A bug here does not
// corrupt a record an operator later notices — it sends live traffic to the
// wrong place, or nowhere.
//
// The store had no test of any kind. It is also rewritten during migration
// (#1203 updates every route's target_ip after a container moves hosts), so
// the upsert-by-domain semantics below are load-bearing for a flow that
// already ships.
//
// Gated on the DSN like the rest of this package, not skipped unconditionally:
// the store-integration lane sets it and asserts these ran.

func routeTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres (the store-integration lane does)")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// newRouteStoreForTest builds a store and removes anything this test creates,
// so runs do not interfere with each other on a shared database.
func newRouteStoreForTest(t *testing.T) (*RouteStore, string) {
	t.Helper()
	ctx := context.Background()
	store, err := NewRouteStore(ctx, routeTestPool(t))
	if err != nil {
		t.Fatalf("NewRouteStore: %v", err)
	}
	// Unique per test so parallel or repeated runs cannot collide on the
	// full_domain UNIQUE constraint.
	suffix := fmt.Sprintf("%s-%d", t.Name(), os.Getpid())
	return store, suffix
}

func TestRouteStore_SaveIsAnUpsertByDomain(t *testing.T) {
	ctx := context.Background()
	store, suffix := newRouteStoreForTest(t)
	domain := "app-" + suffix + ".example.com"
	t.Cleanup(func() { _ = store.Delete(context.Background(), domain) })

	first := &RouteRecord{
		Subdomain: "app-" + suffix, FullDomain: domain,
		TargetIP: "10.0.0.10", TargetPort: 8080, Protocol: "http",
		ContainerName: "alice-container", Active: true,
	}
	if err := store.Save(ctx, first); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The same domain again must UPDATE, not insert a second row — full_domain
	// is UNIQUE, so a non-upsert would error, and a caller re-registering a
	// route after a restart would fail rather than refresh.
	second := *first
	second.TargetIP = "10.0.0.99"
	second.TargetPort = 9090
	if err := store.Save(ctx, &second); err != nil {
		t.Fatalf("re-Save the same domain: %v", err)
	}

	got, err := store.GetByDomain(ctx, domain)
	if err != nil {
		t.Fatalf("GetByDomain: %v", err)
	}
	if got == nil {
		t.Fatal("the route disappeared after being re-saved")
	}
	if got.TargetIP != "10.0.0.99" || got.TargetPort != 9090 {
		t.Errorf("route points at %s:%d, want the updated 10.0.0.99:9090 — this is the write "+
			"MoveContainer makes after a migration, so a stale value sends traffic to the host "+
			"the container just left", got.TargetIP, got.TargetPort)
	}
}

// The migration path: MoveContainer lists a container's routes and rewrites
// each target_ip. Both halves are exercised here because a mismatch between
// them is silent — the write succeeds and the read returns yesterday's IP.
func TestRouteStore_ListByContainerSeesTheRewrittenTarget(t *testing.T) {
	ctx := context.Background()
	store, suffix := newRouteStoreForTest(t)
	container := "movable-" + suffix
	domains := []string{"one-" + suffix + ".example.com", "two-" + suffix + ".example.com"}
	t.Cleanup(func() {
		for _, d := range domains {
			_ = store.Delete(context.Background(), d)
		}
	})

	for i, d := range domains {
		if err := store.Save(ctx, &RouteRecord{
			Subdomain: fmt.Sprintf("s%d-%s", i, suffix), FullDomain: d,
			TargetIP: "10.0.0.10", TargetPort: 8080 + i, Protocol: "http",
			ContainerName: container, Active: true,
		}); err != nil {
			t.Fatalf("Save(%s): %v", d, err)
		}
	}

	routes, err := store.ListByContainer(ctx, container)
	if err != nil {
		t.Fatalf("ListByContainer: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("ListByContainer returned %d routes, want 2 — a migration rewrites what this "+
			"returns, so a missing row is a domain left pointing at the old host", len(routes))
	}

	for _, r := range routes {
		r.TargetIP = "10.9.9.9"
		if err := store.Save(ctx, r); err != nil {
			t.Fatalf("rewrite %s: %v", r.FullDomain, err)
		}
	}

	after, err := store.ListByContainer(ctx, container)
	if err != nil {
		t.Fatalf("ListByContainer after rewrite: %v", err)
	}
	for _, r := range after {
		if r.TargetIP != "10.9.9.9" {
			t.Errorf("%s still points at %s after the rewrite", r.FullDomain, r.TargetIP)
		}
	}
}

// activeOnly is what the gateway filters on. A route that is inactive but
// still served, or active but hidden, is a traffic bug either way.
func TestRouteStore_ActiveFlagFiltersListAndCount(t *testing.T) {
	ctx := context.Background()
	store, suffix := newRouteStoreForTest(t)
	domain := "toggle-" + suffix + ".example.com"
	t.Cleanup(func() { _ = store.Delete(context.Background(), domain) })

	if err := store.Save(ctx, &RouteRecord{
		Subdomain: "toggle-" + suffix, FullDomain: domain,
		TargetIP: "10.0.0.10", TargetPort: 8080, Protocol: "http", Active: true,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	activeBefore, err := store.Count(ctx, true)
	if err != nil {
		t.Fatalf("Count(active): %v", err)
	}

	if err := store.SetActive(ctx, domain, false); err != nil {
		t.Fatalf("SetActive(false): %v", err)
	}

	activeAfter, err := store.Count(ctx, true)
	if err != nil {
		t.Fatalf("Count(active) after deactivation: %v", err)
	}
	if activeAfter != activeBefore-1 {
		t.Errorf("active count went %d -> %d, want a decrease of exactly 1 — the gateway serves "+
			"what this filter returns", activeBefore, activeAfter)
	}

	// And it must still be readable by domain: deactivated is not deleted.
	got, err := store.GetByDomain(ctx, domain)
	if err != nil {
		t.Fatalf("GetByDomain after deactivation: %v", err)
	}
	if got == nil {
		t.Fatal("a deactivated route vanished — it should be inactive, not gone")
	}
	if got.Active {
		t.Error("the route still reports active after SetActive(false)")
	}
}

// An unknown domain must return the SENTINEL, not a generic error.
//
// This is not a style preference. `wake_route_lookup` decides between "no
// such route" and "the database is unhappy" with
// `errors.Is(err, app.ErrRouteNotFound)` — one answers 404, the other 500. If
// absence ever came back as a wrapped generic error, every request for an
// unregistered domain would become a server error, and the store would still
// look correct in isolation.
func TestRouteStore_UnknownDomainReturnsTheNotFoundSentinel(t *testing.T) {
	ctx := context.Background()
	store, suffix := newRouteStoreForTest(t)

	got, err := store.GetByDomain(ctx, "definitely-not-here-"+suffix+".example.com")
	if !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("err = %v, want ErrRouteNotFound — the wake router matches on this sentinel to "+
			"answer 404, so anything else turns an unregistered domain into a 500", err)
	}
	if got != nil {
		t.Errorf("got %+v alongside the not-found error, want nil", got)
	}
}

func TestRouteStore_DeleteRemovesTheRoute(t *testing.T) {
	ctx := context.Background()
	store, suffix := newRouteStoreForTest(t)
	domain := "doomed-" + suffix + ".example.com"

	if err := store.Save(ctx, &RouteRecord{
		Subdomain: "doomed-" + suffix, FullDomain: domain,
		TargetIP: "10.0.0.10", TargetPort: 8080, Protocol: "http", Active: true,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Delete(ctx, domain); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got, err := store.GetByDomain(ctx, domain)
	if !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("after deletion GetByDomain returned (%+v, %v), want ErrRouteNotFound — the "+
			"domain would otherwise keep resolving to a container that no longer serves it",
			got, err)
	}
}
