package network

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres coverage for the passthrough store (#1300).
//
// Passthrough routes are data plane: each record maps an external port on the
// host to a container's IP and port, and a sync job projects them into
// iptables. PostgreSQL is the source of truth and iptables is the mirror, so a
// bug here does not corrupt a record someone later notices — it points a
// public port at the wrong container, or at nothing.
//
// The store had no test of any kind, and it is one of the few whose records
// directly describe a firewall.

func passthroughTestPool(t *testing.T) *pgxpool.Pool {
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

// newPassthroughStoreForTest returns a store plus a port block reserved for
// this test, so runs cannot collide on the (external_port, protocol) unique
// constraint. Ports are derived from the test name rather than allocated, so
// a failure is reproducible.
func newPassthroughStoreForTest(t *testing.T) (PassthroughStore, int) {
	t.Helper()
	ctx := context.Background()
	store, err := NewPassthroughStore(ctx, passthroughTestPool(t))
	if err != nil {
		t.Fatalf("NewPassthroughStore: %v", err)
	}

	// A stable per-test base in the high ephemeral range, offset by PID so
	// concurrent CI jobs against one database do not overlap.
	base := 40000 + (hashName(t.Name())+os.Getpid())%20000
	t.Cleanup(func() {
		for p := base; p < base+10; p++ {
			for _, proto := range []string{"tcp", "udp"} {
				_ = store.Delete(context.Background(), p, proto)
			}
		}
	})
	return store, base
}

func hashName(s string) int {
	h := 0
	for _, r := range s {
		h = h*31 + int(r)
	}
	if h < 0 {
		h = -h
	}
	return h
}

func aRoute(port int, proto, targetIP string) *PassthroughRecord {
	return &PassthroughRecord{
		ExternalPort:  port,
		TargetIP:      targetIP,
		TargetPort:    5432,
		Protocol:      proto,
		ContainerName: "alice-container",
		Description:   "postgres",
		Active:        true,
		CreatedBy:     "alice",
	}
}

// THE constraint: a route is identified by port AND protocol.
//
// If the store keyed on port alone, opening UDP/8080 would overwrite an
// existing TCP/8080 route — silently repointing live TCP traffic at whatever
// the UDP route named. The schema says UNIQUE (external_port, protocol); this
// asserts the store actually behaves that way end to end.
func TestPassthroughStore_PortAndProtocolAreDistinctRoutes(t *testing.T) {
	ctx := context.Background()
	store, base := newPassthroughStoreForTest(t)

	tcp := aRoute(base, "tcp", "10.0.0.10")
	udp := aRoute(base, "udp", "10.0.0.20")
	for _, r := range []*PassthroughRecord{tcp, udp} {
		if err := store.Save(ctx, r); err != nil {
			t.Fatalf("Save(%s/%d): %v", r.Protocol, r.ExternalPort, err)
		}
	}
	if tcp.ID == udp.ID || tcp.ID == "" {
		t.Fatalf("the two protocols share row id %q — one overwrote the other", tcp.ID)
	}

	gotTCP, err := store.GetByPortProtocol(ctx, base, "tcp")
	if err != nil {
		t.Fatalf("GetByPortProtocol(tcp): %v", err)
	}
	if gotTCP.TargetIP != "10.0.0.10" {
		t.Errorf("tcp/%d points at %s, want 10.0.0.10 — the UDP route overwrote it, and live TCP "+
			"traffic on that port now reaches a different container", base, gotTCP.TargetIP)
	}
	gotUDP, err := store.GetByPortProtocol(ctx, base, "udp")
	if err != nil {
		t.Fatalf("GetByPortProtocol(udp): %v", err)
	}
	if gotUDP.TargetIP != "10.0.0.20" {
		t.Errorf("udp/%d points at %s, want 10.0.0.20", base, gotUDP.TargetIP)
	}
}

// Save is an upsert on (port, protocol): re-registering a route after a
// restart must refresh it, not fail on the unique constraint.
func TestPassthroughStore_SaveIsAnUpsertOnPortAndProtocol(t *testing.T) {
	ctx := context.Background()
	store, base := newPassthroughStoreForTest(t)

	first := aRoute(base, "tcp", "10.0.0.10")
	if err := store.Save(ctx, first); err != nil {
		t.Fatalf("Save: %v", err)
	}

	second := aRoute(base, "tcp", "10.9.9.9")
	second.TargetPort = 6432
	if err := store.Save(ctx, second); err != nil {
		t.Fatalf("re-Save the same port/protocol: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("the upsert produced a new row (%s != %s) — the table would accumulate a "+
			"duplicate per restart", second.ID, first.ID)
	}

	got, err := store.GetByPortProtocol(ctx, base, "tcp")
	if err != nil {
		t.Fatalf("GetByPortProtocol: %v", err)
	}
	if got.TargetIP != "10.9.9.9" || got.TargetPort != 6432 {
		t.Errorf("route points at %s:%d, want the updated 10.9.9.9:6432", got.TargetIP, got.TargetPort)
	}
}

// Creation attribution must survive an upsert.
//
// The DO UPDATE list deliberately omits created_by and created_at, so a later
// Save by someone else cannot rewrite who opened the port. That is audit data:
// "who exposed 3306" is a question asked during an incident, and an answer
// that silently became "whoever touched it last" is worse than no answer.
//
// Also asserted on the RETURNED record, not only in the database. The caller
// gets that struct back and may log or display it, so a struct that disagrees
// with the row is the same lie one layer up.
func TestPassthroughStore_UpsertPreservesCreationAttribution(t *testing.T) {
	ctx := context.Background()
	store, base := newPassthroughStoreForTest(t)

	original := aRoute(base, "tcp", "10.0.0.10")
	original.CreatedBy = "alice"
	original.CreatedAt = time.Now().Add(-72 * time.Hour).UTC().Truncate(time.Second)
	if err := store.Save(ctx, original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Somebody else re-saves it, the way a caller who did not read the record
	// first would: zero CreatedAt, their own name.
	later := aRoute(base, "tcp", "10.0.0.11")
	later.CreatedBy = "mallory"
	if err := store.Save(ctx, later); err != nil {
		t.Fatalf("re-Save: %v", err)
	}

	stored, err := store.GetByPortProtocol(ctx, base, "tcp")
	if err != nil {
		t.Fatalf("GetByPortProtocol: %v", err)
	}
	if stored.CreatedBy != "alice" {
		t.Errorf("created_by = %q after someone else re-saved, want alice — the audit trail for "+
			"who opened this port was rewritten by whoever touched it last", stored.CreatedBy)
	}
	if !stored.CreatedAt.UTC().Truncate(time.Second).Equal(original.CreatedAt) {
		t.Errorf("created_at = %v, want the original %v", stored.CreatedAt, original.CreatedAt)
	}

	// The returned struct must agree with the row it just wrote.
	if later.CreatedBy != stored.CreatedBy {
		t.Errorf("Save returned created_by %q while the row says %q — a caller logging the "+
			"returned record reports the wrong creator", later.CreatedBy, stored.CreatedBy)
	}
	if !later.CreatedAt.UTC().Truncate(time.Second).Equal(stored.CreatedAt.UTC().Truncate(time.Second)) {
		t.Errorf("Save returned created_at %v while the row says %v — the record hands back a "+
			"creation time that never happened", later.CreatedAt, stored.CreatedAt)
	}
}

// An empty protocol defaults to tcp, and the default must be visible in what
// comes back: a caller that stored "" and reads "" cannot build the iptables
// rule, which needs a concrete protocol.
func TestPassthroughStore_EmptyProtocolDefaultsToTCP(t *testing.T) {
	ctx := context.Background()
	store, base := newPassthroughStoreForTest(t)

	r := aRoute(base, "", "10.0.0.10")
	if err := store.Save(ctx, r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if r.Protocol != "tcp" {
		t.Errorf("the saved record reports protocol %q, want tcp", r.Protocol)
	}
	if _, err := store.GetByPortProtocol(ctx, base, "tcp"); err != nil {
		t.Errorf("a route saved with an empty protocol is not retrievable as tcp: %v", err)
	}
}

// activeOnly is what the sync job filters on, so a route that is inactive but
// still listed becomes an iptables rule that should not exist.
func TestPassthroughStore_ActiveFlagFiltersListAndCount(t *testing.T) {
	ctx := context.Background()
	store, base := newPassthroughStoreForTest(t)

	if err := store.Save(ctx, aRoute(base, "tcp", "10.0.0.10")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	activeBefore, err := store.Count(ctx, true)
	if err != nil {
		t.Fatalf("Count(active): %v", err)
	}

	if err := store.SetActive(ctx, base, "tcp", false); err != nil {
		t.Fatalf("SetActive(false): %v", err)
	}

	activeAfter, err := store.Count(ctx, true)
	if err != nil {
		t.Fatalf("Count(active) after deactivation: %v", err)
	}
	if activeAfter != activeBefore-1 {
		t.Errorf("active count went %d -> %d, want a decrease of exactly 1 — the sync job builds "+
			"iptables rules from this filter", activeBefore, activeAfter)
	}

	active, err := store.List(ctx, true)
	if err != nil {
		t.Fatalf("List(activeOnly): %v", err)
	}
	for _, r := range active {
		if r.ExternalPort == base && r.Protocol == "tcp" {
			t.Errorf("the deactivated route is still in the active list — it would be programmed " +
				"into iptables anyway")
		}
	}

	// Deactivated is not deleted: the record must still be readable.
	got, err := store.GetByPortProtocol(ctx, base, "tcp")
	if err != nil {
		t.Fatalf("GetByPortProtocol after deactivation: %v", err)
	}
	if got.Active {
		t.Error("the route still reports active after SetActive(false)")
	}
}

// Absence must be the sentinel on every path that can hit it. The three are
// tested together because each is written separately, and a missing one is
// invisible from the others.
func TestPassthroughStore_AbsenceIsTheSentinelEverywhere(t *testing.T) {
	ctx := context.Background()
	store, base := newPassthroughStoreForTest(t)
	absent := base + 5

	t.Run("GetByPortProtocol", func(t *testing.T) {
		got, err := store.GetByPortProtocol(ctx, absent, "tcp")
		if !errors.Is(err, ErrPassthroughNotFound) {
			t.Fatalf("err = %v, want ErrPassthroughNotFound", err)
		}
		if got != nil {
			t.Errorf("got %+v alongside the error, want nil", got)
		}
	})
	t.Run("Delete", func(t *testing.T) {
		if err := store.Delete(ctx, absent, "tcp"); !errors.Is(err, ErrPassthroughNotFound) {
			t.Errorf("err = %v, want ErrPassthroughNotFound — a delete that reports success for a "+
				"route that was never there hides a caller's wrong port", err)
		}
	})
	t.Run("SetActive", func(t *testing.T) {
		if err := store.SetActive(ctx, absent, "tcp", false); !errors.Is(err, ErrPassthroughNotFound) {
			t.Errorf("err = %v, want ErrPassthroughNotFound — silent success here means an "+
				"operator believes they closed a port they did not", err)
		}
	})
}

// Deleting one protocol must not take the other with it — same reasoning as
// the uniqueness test, on the destructive path.
func TestPassthroughStore_DeleteIsScopedToOneProtocol(t *testing.T) {
	ctx := context.Background()
	store, base := newPassthroughStoreForTest(t)

	for _, proto := range []string{"tcp", "udp"} {
		if err := store.Save(ctx, aRoute(base, proto, "10.0.0.10")); err != nil {
			t.Fatalf("Save(%s): %v", proto, err)
		}
	}
	if err := store.Delete(ctx, base, "tcp"); err != nil {
		t.Fatalf("Delete(tcp): %v", err)
	}

	if _, err := store.GetByPortProtocol(ctx, base, "tcp"); !errors.Is(err, ErrPassthroughNotFound) {
		t.Errorf("the tcp route survived its delete: %v", err)
	}
	if _, err := store.GetByPortProtocol(ctx, base, "udp"); err != nil {
		t.Errorf("deleting tcp/%d removed the udp route too (%v) — closing one port silently "+
			"closed another service", base, err)
	}
}

// List is ordered by external_port. The sync job diffs this against iptables,
// and an unstable order makes that diff report churn that is not there.
func TestPassthroughStore_ListIsOrderedByPort(t *testing.T) {
	ctx := context.Background()
	store, base := newPassthroughStoreForTest(t)

	// Saved out of order on purpose.
	for _, offset := range []int{3, 1, 2} {
		if err := store.Save(ctx, aRoute(base+offset, "tcp", "10.0.0.10")); err != nil {
			t.Fatalf("Save(+%d): %v", offset, err)
		}
	}

	all, err := store.List(ctx, false)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var seen []int
	for _, r := range all {
		if r.ExternalPort >= base && r.ExternalPort < base+10 {
			seen = append(seen, r.ExternalPort)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("List returned %d of this test's 3 routes: %v", len(seen), seen)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] < seen[i-1] {
			t.Fatalf("List is not ordered by port: %v", seen)
		}
	}
}

func TestPassthroughStore_SchemaInitIsRepeatable(t *testing.T) {
	ctx := context.Background()
	store, base := newPassthroughStoreForTest(t)

	if err := store.Save(ctx, aRoute(base, "tcp", "10.0.0.10")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := NewPassthroughStore(ctx, passthroughTestPool(t)); err != nil {
		t.Fatalf("re-initialising the schema failed: %v — the daemon would not start twice", err)
	}
	if _, err := store.GetByPortProtocol(ctx, base, "tcp"); err != nil {
		t.Errorf("the route did not survive a schema re-init (%v) — a restart would drop every "+
			"published port", err)
	}
}
