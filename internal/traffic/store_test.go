package traffic

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Postgres coverage for the traffic store (#1300).
//
// This store is where per-container connection history lands: what a container
// talked to, when, and how much. It backs QueryTrafficHistory and
// GetTrafficAggregates, and it is the record an operator reads when asking
// whether a box has been reaching somewhere it should not.
//
// It had no test of any kind, and two of its properties are load-bearing for
// callers that state them as fact in their own comments.

func trafficTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres (the store-integration lane does)")
	}
	store, err := NewStore(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(store.Close)

	// Unique per test so repeated or concurrent runs cannot see each other's
	// rows through the container_name filter every query uses.
	container := fmt.Sprintf("t%d-%s", os.Getpid(), t.Name())
	if len(container) > 60 {
		container = container[:60]
	}
	t.Cleanup(func() {
		_, _ = store.Pool().Exec(context.Background(),
			"DELETE FROM traffic_connections WHERE container_name = $1", container)
		_, _ = store.Pool().Exec(context.Background(),
			"DELETE FROM traffic_aggregates WHERE container_name = $1", container)
	})
	return store, container
}

func aConnection(container, id string, when time.Time) *pb.Connection {
	return &pb.Connection{
		Id:              id,
		ContainerName:   container,
		Protocol:        pb.Protocol_PROTOCOL_TCP,
		SourceIp:        "10.0.0.10",
		SourcePort:      54321,
		DestIp:          "93.184.216.34",
		DestPort:        443,
		Direction:       pb.TrafficDirection_TRAFFIC_DIRECTION_EGRESS,
		BytesSent:       1000,
		BytesReceived:   2000,
		PacketsSent:     10,
		PacketsReceived: 20,
		FirstSeen:       timestamppb.New(when),
		LastSeen:        timestamppb.New(when.Add(30 * time.Second)),
	}
}

func TestTrafficStore_SavedConnectionIsQueryableWithItsCounters(t *testing.T) {
	ctx := context.Background()
	store, container := trafficTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	if err := store.SaveConnection(ctx, aConnection(container, "flow-1", now)); err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}

	got, total, err := store.QueryConnections(ctx, QueryParams{
		ContainerName: container,
		StartTime:     now.Add(-time.Hour),
		EndTime:       now.Add(time.Hour),
		Limit:         10,
	})
	if err != nil {
		t.Fatalf("QueryConnections: %v", err)
	}
	if total != 1 || len(got) != 1 {
		t.Fatalf("got %d row(s) (total %d), want 1 — this is the record an operator reads when "+
			"asking where a container has been connecting", len(got), total)
	}

	c := got[0]
	if c.GetDestIp() != "93.184.216.34" || c.GetDestPort() != 443 {
		t.Errorf("destination = %s:%d, want 93.184.216.34:443", c.GetDestIp(), c.GetDestPort())
	}
	if c.GetBytesSent() != 1000 || c.GetBytesReceived() != 2000 {
		t.Errorf("bytes = %d/%d, want 1000/2000 — the counters are what quota and anomaly "+
			"questions are answered from", c.GetBytesSent(), c.GetBytesReceived())
	}
}

// GetAggregates groups by dest_ip, which is the OTHER read path that scans an
// INET column into a Go string (#1397). Tested separately because the two
// queries are built independently — fixing one and not the other would leave
// the aggregates view broken while history worked, and nothing else would say
// so.
func TestTrafficStore_AggregatesGroupedByDestIPAreReadable(t *testing.T) {
	ctx := context.Background()
	store, container := trafficTestStore(t)
	now := time.Now().UTC().Truncate(time.Hour)

	for i, id := range []string{"agg-a", "agg-b"} {
		conn := aConnection(container, id, now.Add(time.Duration(i)*time.Minute))
		if err := store.SaveConnection(ctx, conn); err != nil {
			t.Fatalf("SaveConnection(%s): %v", id, err)
		}
	}

	aggs, err := store.GetAggregates(ctx, AggregateParams{
		ContainerName: container,
		StartTime:     now.Add(-time.Hour),
		EndTime:       now.Add(time.Hour),
		Interval:      "1h",
		GroupByDestIP: true,
	})
	if err != nil {
		t.Fatalf("GetAggregates: %v — this is the second read path over an INET column, and it "+
			"is built separately from QueryConnections", err)
	}
	if len(aggs) == 0 {
		t.Fatal("no aggregates for two connections just written")
	}
	if got := aggs[0].GetDestIp(); got != "93.184.216.34" {
		t.Errorf("dest_ip = %q, want 93.184.216.34 — grouped-by-IP aggregates name the "+
			"destination, and an empty one makes the view useless", got)
	}
	var sent int64
	for _, a := range aggs {
		sent += a.GetBytesSent()
	}
	if sent != 2000 {
		t.Errorf("summed bytes_sent = %d, want 2000 from two 1000-byte connections", sent)
	}
}

// The container filter is the tenancy boundary of this table: every query goes
// through it, and a leak here shows one tenant another's connection history.
func TestTrafficStore_QueryIsScopedToOneContainer(t *testing.T) {
	ctx := context.Background()
	store, container := trafficTestStore(t)
	other := container + "-other"
	t.Cleanup(func() {
		_, _ = store.Pool().Exec(context.Background(),
			"DELETE FROM traffic_connections WHERE container_name = $1", other)
	})
	now := time.Now().UTC().Truncate(time.Second)

	if err := store.SaveConnection(ctx, aConnection(container, "mine", now)); err != nil {
		t.Fatalf("SaveConnection(mine): %v", err)
	}
	if err := store.SaveConnection(ctx, aConnection(other, "theirs", now)); err != nil {
		t.Fatalf("SaveConnection(theirs): %v", err)
	}

	got, _, err := store.QueryConnections(ctx, QueryParams{
		ContainerName: container,
		StartTime:     now.Add(-time.Hour),
		EndTime:       now.Add(time.Hour),
		Limit:         10,
	})
	if err != nil {
		t.Fatalf("QueryConnections: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want only this container's — a query returning another "+
			"container's connections is a cross-tenant disclosure of who they talk to", len(got))
	}
}

// CHARACTERIZATION (#1394): SaveConnection does NOT deduplicate by flow ID.
//
// `internal/traffic/collector.go` states the opposite twice, in comments that
// justify writing the same flow from two paths:
//
//	"SaveConnection is ON CONFLICT DO NOTHING keyed by the (stable) flow ID,
//	 so a re-evicted flow that briefly reappeared won't duplicate."
//	"SaveConnection is ON CONFLICT DO NOTHING by flow ID, so a flow also
//	 caught by closedFlows on a later poll isn't double-counted."
//
// The INSERT does carry `ON CONFLICT DO NOTHING`, but the table's only unique
// constraint is its BIGSERIAL primary key, which is auto-assigned and can
// never conflict. `conntrack_id` has a plain index, not a unique one — so the
// clause never fires and the same flow is stored as many times as it is
// written. Traffic history and its aggregates over-count by however many
// times a flow was re-observed.
//
// Asserted as it behaves today rather than as it should, so this passes on
// main and FAILS the moment the constraint is added — telling whoever fixes it
// to convert this into the dedup assertion.
func TestTrafficStore_SaveConnectionDoesNotDeduplicateByFlowID(t *testing.T) {
	ctx := context.Background()
	store, container := trafficTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	// The same flow, written twice — exactly what the collector's two paths do.
	for i := 0; i < 2; i++ {
		if err := store.SaveConnection(ctx, aConnection(container, "same-flow-id", now)); err != nil {
			t.Fatalf("SaveConnection #%d: %v", i+1, err)
		}
	}

	_, total, err := store.QueryConnections(ctx, QueryParams{
		ContainerName: container,
		StartTime:     now.Add(-time.Hour),
		EndTime:       now.Add(time.Hour),
		Limit:         10,
	})
	if err != nil {
		t.Fatalf("QueryConnections: %v", err)
	}

	if total == 1 {
		t.Fatalf("#1394 no longer reproduces: the same flow ID stored once.\n\n" +
			"If you added the unique constraint on conntrack_id, this test has done its job — " +
			"replace it with the positive assertion that a re-written flow is stored once, and " +
			"check the migration deduplicated pre-existing rows. Do not delete it: the " +
			"collector's correctness depends on this property.")
	}
	if total != 2 {
		t.Fatalf("the same flow ID stored %d times, expected 2 — the defect exists but its "+
			"shape has changed", total)
	}
	t.Logf("REPRODUCED #1394: the same flow ID is stored %d times. `ON CONFLICT DO NOTHING` "+
		"cannot fire because conntrack_id carries a plain index, not a unique one, and the only "+
		"unique constraint is the auto-assigned BIGSERIAL primary key. Traffic history and its "+
		"aggregates over-count every re-observed flow.", total)
}

// GetConnectionByConntrackID is what a caller reaches for instead of relying
// on the absent constraint, so it has to actually work.
func TestTrafficStore_GetConnectionByConntrackID(t *testing.T) {
	ctx := context.Background()
	store, container := trafficTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	id := container + "-conntrack"
	if err := store.SaveConnection(ctx, aConnection(container, id, now)); err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}

	present, err := store.GetConnectionByConntrackID(ctx, id)
	if err != nil {
		t.Fatalf("GetConnectionByConntrackID: %v", err)
	}
	if !present {
		t.Error("a stored flow reports as absent — the check-then-insert path callers use " +
			"instead of the missing constraint would duplicate every flow")
	}

	absent, err := store.GetConnectionByConntrackID(ctx, id+"-nope")
	if err != nil {
		t.Fatalf("GetConnectionByConntrackID(absent): %v", err)
	}
	if absent {
		t.Error("an unstored flow reports as present — the same path would then DROP every flow")
	}
}

// CHARACTERIZATION (#1395): Cleanup does not touch traffic_aggregates.
//
// `Cleanup(retentionDays)` deletes from traffic_connections only. The
// collector calls it on a timer as the retention mechanism, and
// traffic_aggregates has no cleanup anywhere — so aggregates accumulate for
// the lifetime of the deployment, on a table with a row per container per
// destination per interval.
//
// Pinned the same way as the dedup defect above: passes on main, fails when
// fixed.
func TestTrafficStore_CleanupLeavesAggregatesBehind(t *testing.T) {
	ctx := context.Background()
	store, container := trafficTestStore(t)

	// An aggregate well outside any sane retention window.
	old := time.Now().UTC().AddDate(0, 0, -400).Truncate(time.Second)
	agg := &pb.TrafficAggregate{
		DestIp:          "93.184.216.34",
		DestPort:        443,
		BytesSent:       10,
		BytesReceived:   20,
		ConnectionCount: 1,
		Timestamp:       timestamppb.New(old),
	}
	if err := store.SaveAggregate(ctx, agg, container, old.Add(time.Hour)); err != nil {
		t.Fatalf("SaveAggregate: %v", err)
	}

	if err := store.Cleanup(ctx, 30); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	var remaining int
	if err := store.Pool().QueryRow(ctx,
		"SELECT COUNT(*) FROM traffic_aggregates WHERE container_name = $1", container,
	).Scan(&remaining); err != nil {
		t.Fatalf("count aggregates: %v", err)
	}

	if remaining == 0 {
		t.Fatalf("#1395 no longer reproduces: Cleanup removed a 400-day-old aggregate.\n\n" +
			"If you extended Cleanup to cover traffic_aggregates, this test has done its job — " +
			"replace it with the positive assertion that aggregates past the retention window " +
			"are removed and recent ones are not.")
	}
	t.Logf("REPRODUCED #1395: a 400-day-old aggregate survived Cleanup(30 days). Cleanup deletes "+
		"from traffic_connections only, and nothing anywhere removes rows from "+
		"traffic_aggregates — %d row(s) remain", remaining)
}

// Retention must actually delete what it claims to, on the table it does cover.
func TestTrafficStore_CleanupRemovesConnectionsPastRetention(t *testing.T) {
	ctx := context.Background()
	store, container := trafficTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	if err := store.SaveConnection(ctx, aConnection(container, "recent", now)); err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}
	// created_at defaults to NOW(), which is what Cleanup filters on, so an old
	// row has to be aged directly.
	if err := store.SaveConnection(ctx, aConnection(container, "ancient", now)); err != nil {
		t.Fatalf("SaveConnection(ancient): %v", err)
	}
	if _, err := store.Pool().Exec(ctx,
		"UPDATE traffic_connections SET created_at = $1 WHERE conntrack_id = 'ancient'",
		now.AddDate(0, 0, -400)); err != nil {
		t.Fatalf("age the ancient row: %v", err)
	}

	if err := store.Cleanup(ctx, 30); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	var recent, ancient bool
	var err error
	if recent, err = store.GetConnectionByConntrackID(ctx, "recent"); err != nil {
		t.Fatalf("check recent: %v", err)
	}
	if ancient, err = store.GetConnectionByConntrackID(ctx, "ancient"); err != nil {
		t.Fatalf("check ancient: %v", err)
	}
	if ancient {
		t.Error("a 400-day-old connection survived Cleanup(30) — retention does not retain")
	}
	if !recent {
		t.Error("Cleanup(30) deleted a connection created seconds ago — retention is deleting " +
			"live history")
	}
}

func TestTrafficStore_SchemaInitIsRepeatable(t *testing.T) {
	ctx := context.Background()
	store, container := trafficTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	if err := store.SaveConnection(ctx, aConnection(container, "survivor", now)); err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}
	second, err := NewStore(ctx, os.Getenv("CONTAINARIUM_TEST_DSN"))
	if err != nil {
		t.Fatalf("re-initialising the schema failed: %v — the daemon would not start twice", err)
	}
	defer second.Close()

	present, err := store.GetConnectionByConntrackID(ctx, "survivor")
	if err != nil {
		t.Fatalf("GetConnectionByConntrackID: %v", err)
	}
	if !present {
		t.Error("the connection did not survive a schema re-init — a restart would erase history")
	}
}
