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

// Trenyx audit finding #2 (2026-09-16): Save was an unconditional upsert by
// full_domain with no ownership comparison, so a caller (an admin via
// AddRoute, or a future automated path) naming a hostname that already
// belongs to a different creator would silently repoint it — potentially
// stealing traffic addressed to another tenant's container. This test
// proves the refusal.
func TestRouteStore_SaveRefusesToRebindADifferentCreatorsHostname(t *testing.T) {
	ctx := context.Background()
	store, suffix := newRouteStoreForTest(t)
	domain := "owned-" + suffix + ".example.com"
	t.Cleanup(func() { _ = store.Delete(context.Background(), domain) })

	if err := store.Save(ctx, &RouteRecord{
		Subdomain: "owned-" + suffix, FullDomain: domain,
		TargetIP: "10.0.0.10", TargetPort: 8080, Protocol: "http",
		Active: true, CreatedBy: "alice",
	}); err != nil {
		t.Fatalf("initial Save: %v", err)
	}

	// A different creator naming the same hostname must be refused, not
	// silently rebound to their own target.
	err := store.Save(ctx, &RouteRecord{
		Subdomain: "owned-" + suffix, FullDomain: domain,
		TargetIP: "10.6.6.6", TargetPort: 9999, Protocol: "http",
		Active: true, CreatedBy: "mallory",
	})
	if !errors.Is(err, ErrRouteOwnershipConflict) {
		t.Fatalf("err = %v, want ErrRouteOwnershipConflict", err)
	}

	// And the route must be untouched by the refused attempt.
	got, gerr := store.GetByDomain(ctx, domain)
	if gerr != nil {
		t.Fatalf("GetByDomain: %v", gerr)
	}
	if got.TargetIP != "10.0.0.10" || got.TargetPort != 8080 {
		t.Errorf("route now points at %s:%d — the refused Save must not have partially applied",
			got.TargetIP, got.TargetPort)
	}
	if got.CreatedBy != "alice" {
		t.Errorf("created_by = %q, want the original creator %q to be preserved", got.CreatedBy, "alice")
	}
}

// The same creator re-saving (the normal case: AddRoute rewriting its own
// route, MoveContainer rewriting target_ip after a migration, cloud
// reconciliation refreshing its own routes) must keep working exactly like
// before this check existed.
func TestRouteStore_SaveAllowsTheSameCreatorToUpdate(t *testing.T) {
	ctx := context.Background()
	store, suffix := newRouteStoreForTest(t)
	domain := "sameowner-" + suffix + ".example.com"
	t.Cleanup(func() { _ = store.Delete(context.Background(), domain) })

	first := &RouteRecord{
		Subdomain: "sameowner-" + suffix, FullDomain: domain,
		TargetIP: "10.0.0.10", TargetPort: 8080, Protocol: "http",
		Active: true, CreatedBy: "alice",
	}
	if err := store.Save(ctx, first); err != nil {
		t.Fatalf("initial Save: %v", err)
	}

	second := *first
	second.TargetIP = "10.0.0.99"
	if err := store.Save(ctx, &second); err != nil {
		t.Fatalf("re-Save by the same creator: %v", err)
	}

	got, err := store.GetByDomain(ctx, domain)
	if err != nil {
		t.Fatalf("GetByDomain: %v", err)
	}
	if got.TargetIP != "10.0.0.99" {
		t.Errorf("target_ip = %q, want the update to have applied", got.TargetIP)
	}
}

// A route saved before this check existed (created_by empty — the state of
// every route already in production) must not lock operators out on
// upgrade. It also must not stay unprotected forever: the first touch after
// upgrade backfills created_by, so the row is protected from then on.
func TestRouteStore_SaveBackfillsOwnerOnLegacyRouteThenProtectsIt(t *testing.T) {
	ctx := context.Background()
	store, suffix := newRouteStoreForTest(t)
	domain := "legacy-" + suffix + ".example.com"
	t.Cleanup(func() { _ = store.Delete(context.Background(), domain) })

	// Simulates a pre-upgrade row: no CreatedBy.
	if err := store.Save(ctx, &RouteRecord{
		Subdomain: "legacy-" + suffix, FullDomain: domain,
		TargetIP: "10.0.0.10", TargetPort: 8080, Protocol: "http", Active: true,
	}); err != nil {
		t.Fatalf("initial (legacy, ownerless) Save: %v", err)
	}

	// First post-upgrade touch: not refused (empty creator is exempt), and
	// it claims the row for whoever touched it first.
	if err := store.Save(ctx, &RouteRecord{
		Subdomain: "legacy-" + suffix, FullDomain: domain,
		TargetIP: "10.0.0.20", TargetPort: 8080, Protocol: "http",
		Active: true, CreatedBy: "alice",
	}); err != nil {
		t.Fatalf("first post-upgrade Save: %v", err)
	}

	got, err := store.GetByDomain(ctx, domain)
	if err != nil {
		t.Fatalf("GetByDomain: %v", err)
	}
	if got.CreatedBy != "alice" {
		t.Fatalf("created_by = %q after first touch, want backfilled to %q", got.CreatedBy, "alice")
	}

	// Now that it's owned, a different creator must be refused.
	err = store.Save(ctx, &RouteRecord{
		Subdomain: "legacy-" + suffix, FullDomain: domain,
		TargetIP: "10.6.6.6", TargetPort: 9999, Protocol: "http",
		Active: true, CreatedBy: "mallory",
	})
	if !errors.Is(err, ErrRouteOwnershipConflict) {
		t.Fatalf("err = %v, want ErrRouteOwnershipConflict now that the route has an owner", err)
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
