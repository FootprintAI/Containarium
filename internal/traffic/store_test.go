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
	// The bare address, with no /32 — a plain ::text cast on an INET appends
	// the netmask, and an address that does not compare equal to the one the
	// caller stored is worse than an error.
	if c.GetDestIp() != "93.184.216.34" || c.GetDestPort() != 443 {
		t.Errorf("destination = %s:%d, want 93.184.216.34:443 (no netmask suffix)",
			c.GetDestIp(), c.GetDestPort())
	}
	if c.GetSourceIp() != "10.0.0.10" {
		t.Errorf("source = %s, want 10.0.0.10 (no netmask suffix)", c.GetSourceIp())
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

// #1394: SaveConnection deduplicates by flow ID.
//
// `internal/traffic/collector.go` writes the same flow from two paths (an
// LRU-evicted flow briefly reappearing, and a flow also caught by
// closedFlows on a later poll) on the strength of this being true — a
// unique index on conntrack_id, which `ON CONFLICT DO NOTHING` targets, so
// the second write of the same flow is silently dropped rather than
// double-counted.
func TestTrafficStore_SaveConnectionDeduplicatesByFlowID(t *testing.T) {
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
	if total != 1 {
		t.Fatalf("the same flow ID stored %d time(s), want 1 — a flow re-observed by either of "+
			"the collector's two write paths must not be double-counted", total)
	}
}

// #1394: the migration that added conntrack_id's unique index also had to
// deduplicate whatever the defect had already written, since a unique
// index cannot be created while duplicates exist. Simulates the
// pre-migration state directly (drop the unique index, insert duplicates
// the way the un-constrained INSERT used to allow) and re-runs initSchema,
// which is exactly what happens when an existing deployment upgrades onto
// this fix.
func TestTrafficStore_MigrationDeduplicatesPreExistingRows(t *testing.T) {
	ctx := context.Background()
	store, container := trafficTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	flowID := container + "-dup"

	if _, err := store.Pool().Exec(ctx,
		"DROP INDEX IF EXISTS idx_traffic_conntrack_id_unique"); err != nil {
		t.Fatalf("drop unique index (simulating pre-migration): %v", err)
	}
	// Restore the index even if this test fails partway through (e.g. an
	// insert below), so a shared test database is never left without
	// the constraint for whatever runs after this test.
	t.Cleanup(func() { _ = store.initSchema(context.Background()) })

	insert := func(bytesSent int64) {
		if _, err := store.Pool().Exec(ctx, `
			INSERT INTO traffic_connections (
				container_name, protocol, source_ip, dest_ip, dest_port,
				direction, bytes_sent, bytes_received, started_at, conntrack_id
			) VALUES ($1, 6, '10.0.0.10', '93.184.216.34', 443, 1, $2, 0, $3, $4)
		`, container, bytesSent, now, flowID); err != nil {
			t.Fatalf("insert pre-migration duplicate: %v", err)
		}
	}
	// Three duplicates of the same flow, as the un-constrained collector
	// would have written them across retries: partial, then two closer
	// to the real (cumulative, larger) total — the largest must survive.
	insert(100)
	insert(900)
	insert(500)

	// A row with no flow ID at all must never be treated as a duplicate
	// of another NULL row — Postgres itself already guarantees this
	// under a unique index (two NULLs never compare equal), so this
	// pins that the dedup step doesn't do something more aggressive.
	if _, err := store.Pool().Exec(ctx, `
		INSERT INTO traffic_connections (
			container_name, protocol, source_ip, dest_ip, dest_port,
			direction, bytes_sent, bytes_received, started_at, conntrack_id
		) VALUES ($1, 6, '10.0.0.10', '93.184.216.34', 443, 1, 42, 0, $2, NULL)
	`, container, now); err != nil {
		t.Fatalf("insert null-conntrack-id row: %v", err)
	}

	if err := store.initSchema(ctx); err != nil {
		t.Fatalf("re-run initSchema (the migration): %v", err)
	}

	rows, err := store.Pool().Query(ctx,
		"SELECT bytes_sent FROM traffic_connections WHERE container_name = $1 AND conntrack_id = $2",
		container, flowID)
	if err != nil {
		t.Fatalf("query surviving rows: %v", err)
	}
	defer rows.Close()
	var survivors []int64
	for rows.Next() {
		var b int64
		if err := rows.Scan(&b); err != nil {
			t.Fatalf("scan: %v", err)
		}
		survivors = append(survivors, b)
	}
	if len(survivors) != 1 {
		t.Fatalf("survivors = %v, want exactly 1 row per conntrack_id after the migration", survivors)
	}
	if survivors[0] != 900 {
		t.Errorf("surviving row has bytes_sent=%d, want 900 (the largest — the collector's "+
			"counters are cumulative, so the row that observed the flow longest is the most "+
			"complete one to keep)", survivors[0])
	}

	var nullCount int
	if err := store.Pool().QueryRow(ctx,
		"SELECT count(*) FROM traffic_connections WHERE container_name = $1 AND conntrack_id IS NULL",
		container).Scan(&nullCount); err != nil {
		t.Fatalf("count null-conntrack-id rows: %v", err)
	}
	if nullCount != 1 {
		t.Errorf("null-conntrack_id rows = %d, want 1 (untouched) — a row with no flow ID must "+
			"never be swept up as if it duplicated another", nullCount)
	}
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

// Cleanup must remove traffic_aggregates rows past their retention window,
// and leave recent ones alone (#1395: it used to touch traffic_connections
// only, so aggregates accumulated for the lifetime of the deployment).
//
// The aggregates window is a deliberate multiple of retentionDays
// (aggregateRetentionMultiplier), not the same value — so Cleanup(30) here
// is only exercised against an aggregate old enough to be well past ANY
// sane multiple of 30 days, and a recent one that survives regardless of
// which multiple is configured.
func TestTrafficStore_CleanupRemovesAggregatesPastRetention(t *testing.T) {
	ctx := context.Background()
	store, container := trafficTestStore(t)

	old := time.Now().UTC().AddDate(0, 0, -400).Truncate(time.Second)
	oldAgg := &pb.TrafficAggregate{
		DestIp:          "93.184.216.34",
		DestPort:        443,
		BytesSent:       10,
		BytesReceived:   20,
		ConnectionCount: 1,
		Timestamp:       timestamppb.New(old),
	}
	if err := store.SaveAggregate(ctx, oldAgg, container, old.Add(time.Hour)); err != nil {
		t.Fatalf("SaveAggregate(old): %v", err)
	}

	recent := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	recentAgg := &pb.TrafficAggregate{
		DestIp:          "93.184.216.34",
		DestPort:        443,
		BytesSent:       30,
		BytesReceived:   40,
		ConnectionCount: 1,
		Timestamp:       timestamppb.New(recent),
	}
	if err := store.SaveAggregate(ctx, recentAgg, container, recent.Add(time.Hour)); err != nil {
		t.Fatalf("SaveAggregate(recent): %v", err)
	}

	if err := store.Cleanup(ctx, 30); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	var remainingStarts []time.Time
	rows, err := store.Pool().Query(ctx,
		"SELECT interval_start FROM traffic_aggregates WHERE container_name = $1", container)
	if err != nil {
		t.Fatalf("query aggregates: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ts time.Time
		if err := rows.Scan(&ts); err != nil {
			t.Fatalf("scan interval_start: %v", err)
		}
		remainingStarts = append(remainingStarts, ts)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate aggregates: %v", err)
	}

	if len(remainingStarts) != 1 {
		t.Fatalf("got %d aggregate row(s) after Cleanup, want exactly 1 (the recent one): %v",
			len(remainingStarts), remainingStarts)
	}
	got := remainingStarts[0]
	if got.Before(recent.Add(-time.Minute)) || got.After(recent.Add(time.Minute)) {
		t.Fatalf("surviving aggregate has interval_start %v, want the recent one (~%v) — the 400-day-old one (%v) should be the one removed",
			got, recent, old)
	}
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
