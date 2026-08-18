//go:build integration

// Integration coverage for the cluster Store implementations (#1413).
//
// Same rule as internal/server/store_integration_test.go (#1300): the
// SAME assertions run against the in-memory and Postgres impls, so the
// contract is stated once and a divergence is a failure, not a
// discovery. The DSN is required, not defaulted — failing beats
// silently skipping.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/cluster/
package cluster

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Fatal("CONTAINARIUM_TEST_DSN is unset. This build tag exists to run against a real " +
			"database; failing rather than skipping, so a lane that loses its service container " +
			"reports it instead of going quietly green.")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func freshSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{
		`DROP TABLE IF EXISTS k8s_cluster_events`,
		`DROP TABLE IF EXISTS k8s_cluster_nodes`,
		`DROP TABLE IF EXISTS k8s_clusters`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("reset schema (%s): %v", q, err)
		}
	}
}

func stores(t *testing.T) map[string]Store {
	t.Helper()
	pool := testPool(t)
	freshSchema(t, pool)
	pg, err := NewPGStore(context.Background(), pool)
	if err != nil {
		t.Fatalf("NewPGStore: %v", err)
	}
	return map[string]Store{"mem": NewMemStore(), "postgres": pg}
}

func mkCluster(owner, name string) *Cluster {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &Cluster{
		ID: uuid.NewString(), Owner: owner, Name: name,
		State: StateProvisioning, NodeGroups: DefaultNodeGroups(),
		CreatedAt: now, UpdatedAt: now,
	}
}

func TestClusterStore_ContractHoldsForBothImpls(t *testing.T) {
	ctx := context.Background()
	for impl, s := range stores(t) {
		t.Run(impl, func(t *testing.T) {
			// Create + duplicate.
			c := mkCluster("alice", "demo")
			if err := s.Create(ctx, c); err != nil {
				t.Fatalf("Create: %v", err)
			}
			if err := s.Create(ctx, mkCluster("alice", "demo")); !errors.Is(err, ErrAlreadyExists) {
				t.Fatalf("duplicate Create = %v, want ErrAlreadyExists", err)
			}
			// Same name, different owner is fine.
			if err := s.Create(ctx, mkCluster("bob", "demo")); err != nil {
				t.Fatalf("Create other owner: %v", err)
			}

			// Get round-trips the typed node groups.
			got, err := s.Get(ctx, "alice", "demo")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if len(got.NodeGroups) != 3 || got.NodeGroups[0].Name != "small" || got.NodeGroups[0].Size.Memory != "4GB" {
				t.Fatalf("node groups did not round-trip: %+v", got.NodeGroups)
			}
			if got.State != StateProvisioning {
				t.Fatalf("state = %q, want provisioning", got.State)
			}
			if _, err := s.Get(ctx, "alice", "nope"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get missing = %v, want ErrNotFound", err)
			}

			// List is owner-scoped; "" lists all.
			all, err := s.List(ctx, "")
			if err != nil || len(all) != 2 {
				t.Fatalf("List all = %d clusters (%v), want 2", len(all), err)
			}
			mine, err := s.List(ctx, "alice")
			if err != nil || len(mine) != 1 || mine[0].Owner != "alice" {
				t.Fatalf("List alice = %+v (%v), want 1 owned cluster", mine, err)
			}

			// State + endpoint transitions.
			if err := s.SetState(ctx, "alice", "demo", StateReady, ""); err != nil {
				t.Fatalf("SetState: %v", err)
			}
			if err := s.SetEndpoint(ctx, "alice", "demo", "203.0.113.10:30443"); err != nil {
				t.Fatalf("SetEndpoint: %v", err)
			}
			got, _ = s.Get(ctx, "alice", "demo")
			if got.State != StateReady || got.APIEndpoint != "203.0.113.10:30443" {
				t.Fatalf("after updates: state=%q endpoint=%q", got.State, got.APIEndpoint)
			}
			if err := s.SetState(ctx, "alice", "nope", StateReady, ""); !errors.Is(err, ErrNotFound) {
				t.Fatalf("SetState missing = %v, want ErrNotFound", err)
			}

			// UpdateNodeGroups replaces the set.
			if err := s.UpdateNodeGroups(ctx, "alice", "demo", []NodeGroup{
				{Name: "small", Size: Size{CPU: "2", Memory: "4GB", Disk: "40GB"}, MinNodes: 2, MaxNodes: 5},
			}); err != nil {
				t.Fatalf("UpdateNodeGroups: %v", err)
			}
			got, _ = s.Get(ctx, "alice", "demo")
			if len(got.NodeGroups) != 1 || got.NodeGroups[0].MaxNodes != 5 {
				t.Fatalf("groups after update: %+v", got.NodeGroups)
			}

			// Nodes: upsert requires the cluster; a re-upsert replaces the
			// WHOLE record (created_at included) identically on both impls.
			created := time.Now().UTC().Truncate(time.Millisecond)
			node := &Node{Owner: "alice", Cluster: "demo", VMName: "alice-k8s-demo-small-1",
				Role: RoleWorker, Group: "small", State: NodeStateProvisioning, CreatedAt: created}
			if err := s.UpsertNode(ctx, node); err != nil {
				t.Fatalf("UpsertNode: %v", err)
			}
			node.State = NodeStateReady
			node.CreatedAt = created.Add(time.Hour) // replaced node, reused VM name
			if err := s.UpsertNode(ctx, node); err != nil {
				t.Fatalf("UpsertNode update: %v", err)
			}
			orphan := &Node{Owner: "alice", Cluster: "nope", VMName: "x", Role: RoleWorker, State: NodeStateReady, CreatedAt: created}
			if err := s.UpsertNode(ctx, orphan); !errors.Is(err, ErrNotFound) {
				t.Fatalf("UpsertNode orphan = %v, want ErrNotFound", err)
			}
			nodes, err := s.ListNodes(ctx, "alice", "demo")
			if err != nil || len(nodes) != 1 || nodes[0].State != NodeStateReady {
				t.Fatalf("ListNodes = %+v (%v), want 1 ready node", nodes, err)
			}
			if !nodes[0].CreatedAt.Equal(created.Add(time.Hour)) {
				t.Fatalf("re-upsert kept stale created_at %v, want %v", nodes[0].CreatedAt, created.Add(time.Hour))
			}
			// ListNodes on a missing cluster is NotFound, not (nil, nil) —
			// a reconciler must distinguish "empty" from "gone".
			if _, err := s.ListNodes(ctx, "alice", "nope"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("ListNodes missing cluster = %v, want ErrNotFound", err)
			}

			// DeleteNode is (owner, cluster)-scoped: the same VM name is
			// not deletable through someone else's cluster.
			if err := s.DeleteNode(ctx, "bob", "demo", "alice-k8s-demo-small-1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("cross-cluster DeleteNode = %v, want ErrNotFound", err)
			}
			if err := s.DeleteNode(ctx, "alice", "demo", "alice-k8s-demo-small-1"); err != nil {
				t.Fatalf("DeleteNode: %v", err)
			}
			if err := s.DeleteNode(ctx, "alice", "demo", "alice-k8s-demo-small-1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("second DeleteNode = %v, want ErrNotFound", err)
			}
			// Re-add so the delete-cascade assertions below still see a node.
			if err := s.UpsertNode(ctx, node); err != nil {
				t.Fatalf("UpsertNode re-add: %v", err)
			}

			// Events: append-ordered, newest first, limit respected.
			base := time.Now().UTC().Truncate(time.Millisecond)
			for i, reason := range []string{"first", "second", "third"} {
				e := Event{At: base.Add(time.Duration(i) * time.Second), Kind: EventScaleUp, Group: "small", Reason: reason}
				if err := s.AppendEvent(ctx, "alice", "demo", e); err != nil {
					t.Fatalf("AppendEvent: %v", err)
				}
			}
			evs, err := s.ListEvents(ctx, "alice", "demo", 2)
			if err != nil {
				t.Fatalf("ListEvents: %v", err)
			}
			if len(evs) != 2 || evs[0].Reason != "third" || evs[1].Reason != "second" {
				t.Fatalf("ListEvents(2) = %+v, want newest-first [third second]", evs)
			}

			// Delete removes the cluster AND its nodes/events; the name is
			// immediately reusable and the re-created cluster starts empty.
			if err := s.Delete(ctx, "alice", "demo"); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if err := s.Delete(ctx, "alice", "demo"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("second Delete = %v, want ErrNotFound", err)
			}
			if err := s.Create(ctx, mkCluster("alice", "demo")); err != nil {
				t.Fatalf("re-Create after delete: %v", err)
			}
			nodes, err = s.ListNodes(ctx, "alice", "demo")
			if err != nil || len(nodes) != 0 {
				t.Fatalf("nodes after re-create = %+v (%v), want none", nodes, err)
			}
			evs, err = s.ListEvents(ctx, "alice", "demo", 0)
			if err != nil || len(evs) != 0 {
				t.Fatalf("events after re-create = %+v (%v), want none", evs, err)
			}
		})
	}
}

// The isolation class is part of the cluster row, not a server-side
// afterthought: both impls must round-trip it, and both must resolve an
// unset value to the safe class (#1428). A store that quietly persisted
// "" would make "which clusters share a kernel with this host"
// unanswerable from the data.
func TestClusterStore_NodeIsolationRoundTrips(t *testing.T) {
	ctx := context.Background()
	for impl, s := range stores(t) {
		t.Run(impl, func(t *testing.T) {
			// Explicit container isolation round-trips verbatim.
			cc := mkCluster("alice", "shared-kernel")
			cc.NodeIsolation = IsolationContainer
			if err := s.Create(ctx, cc); err != nil {
				t.Fatalf("Create container cluster: %v", err)
			}
			// Explicit vm isolation round-trips verbatim.
			cv := mkCluster("alice", "hw-isolated")
			cv.NodeIsolation = IsolationVM
			if err := s.Create(ctx, cv); err != nil {
				t.Fatalf("Create vm cluster: %v", err)
			}
			// An unset class is persisted as the safe default, not as "".
			cu := mkCluster("alice", "unset")
			if err := s.Create(ctx, cu); err != nil {
				t.Fatalf("Create unset cluster: %v", err)
			}

			for name, want := range map[string]Isolation{
				"shared-kernel": IsolationContainer,
				"hw-isolated":   IsolationVM,
				"unset":         IsolationVM,
			} {
				got, err := s.Get(ctx, "alice", name)
				if err != nil {
					t.Fatalf("Get %s: %v", name, err)
				}
				if got.NodeIsolation != want {
					t.Fatalf("Get %s isolation = %q, want %q", name, got.NodeIsolation, want)
				}
			}

			// List carries it too — the auditor's query is a list, not a
			// walk of individual gets.
			all, err := s.List(ctx, "alice")
			if err != nil || len(all) != 3 {
				t.Fatalf("List = %d clusters (%v), want 3", len(all), err)
			}
			for _, c := range all {
				if c.NodeIsolation != IsolationVM && c.NodeIsolation != IsolationContainer {
					t.Fatalf("List %s isolation = %q, want a resolved class", c.Name, c.NodeIsolation)
				}
			}
		})
	}
}

// Rows written before this column existed must read back as VM, never
// as "" — the migration decides the class of every legacy cluster, and
// the only safe answer is the strong one. Postgres-only: MemStore has
// no on-disk history to migrate.
func TestClusterStore_LegacyRowsDefaultToVM(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	freshSchema(t, pool)

	// The pre-#1428 k8s_clusters shape, and a row inside it.
	if _, err := pool.Exec(ctx, `
		CREATE TABLE k8s_clusters (
			id UUID PRIMARY KEY,
			owner TEXT NOT NULL,
			name TEXT NOT NULL,
			state TEXT NOT NULL,
			state_reason TEXT NOT NULL DEFAULT '',
			k3s_version TEXT NOT NULL DEFAULT '',
			api_endpoint TEXT NOT NULL DEFAULT '',
			node_groups JSONB NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,
			UNIQUE(owner, name)
		)`); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `
		INSERT INTO k8s_clusters (id, owner, name, state, node_groups, created_at, updated_at)
		VALUES ($1, 'alice', 'legacy', 'ready', '[]'::jsonb, $2, $2)`,
		uuid.NewString(), now); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	// The constructor migrates in place; the legacy row keeps its data.
	s, err := NewPGStore(ctx, pool)
	if err != nil {
		t.Fatalf("NewPGStore over legacy schema: %v", err)
	}
	got, err := s.Get(ctx, "alice", "legacy")
	if err != nil {
		t.Fatalf("Get legacy row: %v", err)
	}
	if got.NodeIsolation != IsolationVM {
		t.Fatalf("legacy row isolation = %q, want %q", got.NodeIsolation, IsolationVM)
	}
}
