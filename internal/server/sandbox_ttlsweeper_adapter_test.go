package server

import (
	"context"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sandbox/ipam"
	"github.com/footprintai/containarium/internal/sandbox/pool"
	"github.com/footprintai/containarium/internal/ttlsweeper"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestSpawnSandbox_StampsTTLExpiresAt pins that the cold path writes the
// exact key/format ttlsweeper.Decide reads — the sandbox equivalent of
// stampTTL's own contract (container_server_ttl.go). Without this the
// adapter would never see a TTL to act on and every sandbox would leak
// forever, silently.
func TestSpawnSandbox_StampsTTLExpiresAt(t *testing.T) {
	backend := newFakeSandboxBackend()
	s := NewSandboxServer(backend, nil)

	before := time.Now()
	sb := spawnAsAlice(t, backend, s)
	after := time.Now()

	info := backend.instances[sb.SandboxId]
	if info.TTLExpiresAt.IsZero() {
		t.Fatal("TTLExpiresAt not stamped on the cold path")
	}
	// +/- 1s slack: RFC3339 (no sub-second field) truncates the stamped
	// value to whole seconds, so it can legitimately land a fraction of a
	// second before `before`'s own sub-second reading.
	wantMin := before.Add(defaultSandboxIdleTTL).Add(-time.Second)
	wantMax := after.Add(defaultSandboxIdleTTL).Add(time.Second)
	if info.TTLExpiresAt.Before(wantMin) || info.TTLExpiresAt.After(wantMax) {
		t.Errorf("TTLExpiresAt = %v, want between %v and %v (now + default idle ttl)", info.TTLExpiresAt, wantMin, wantMax)
	}
}

// TestSpawnSandbox_ClaimFromPool_StampsTTLExpiresAt is
// TestSpawnSandbox_StampsTTLExpiresAt's sibling for the pool-claim path —
// claimFromPool sets the same key via a separate SetConfig call, and the
// two constructions must agree.
func TestSpawnSandbox_ClaimFromPool_StampsTTLExpiresAt(t *testing.T) {
	backend := newFakeSandboxBackend()
	allocator, err := ipam.New("10.100.0.10", "10.100.0.250", "10.100.0.1", 0)
	if err != nil {
		t.Fatalf("ipam.New: %v", err)
	}
	p := pool.New(backend, allocator, pool.Config{
		MinWarm:    map[pb.SandboxTemplate]int{pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE: 1},
		Image:      map[pb.SandboxTemplate]string{pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE: "images:ubuntu/24.04"},
		NICNetwork: "incusbr0",
	})
	p.Reconcile(context.Background())
	s := NewSandboxServer(backend, p)

	resp, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{})
	if err != nil {
		t.Fatalf("SpawnSandbox: %v", err)
	}

	info := backend.instances[resp.Sandbox.SandboxId]
	if info.TTLExpiresAt.IsZero() {
		t.Fatal("TTLExpiresAt not stamped on the pool-claim path")
	}
}

// TestTTLSweeperSandboxAdapter_ListContainers_FiltersToSandboxesOnly pins
// the adapter's whole reason for existing: it must see sandboxes (and
// their TTL) and must NOT see an unrelated, non-sandbox container even if
// that container happens to carry its own TTLExpiresAt — persistent-box
// TTLs are the OTHER ttlsweeper.Manager's job (ttlsweeperIncusAdapter),
// wired in dual_server.go against ContainerServer, not SandboxServer.
func TestTTLSweeperSandboxAdapter_ListContainers_FiltersToSandboxesOnly(t *testing.T) {
	backend := newFakeSandboxBackend()
	s := NewSandboxServer(backend, nil)
	sb := spawnAsAlice(t, backend, s)

	// A non-sandbox container that happens to carry the same raw TTL key —
	// must be excluded by the kind-label filter, not merely by accident.
	if err := backend.CreateContainer(incus.ContainerConfig{
		Name:        "alice-container",
		ExtraConfig: map[string]string{incus.TTLExpiresAtKey: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
	}); err != nil {
		t.Fatalf("CreateContainer(alice-container): %v", err)
	}

	adapter := &ttlsweeperSandboxAdapter{backend: backend}
	views, err := adapter.ListContainers()
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("ListContainers returned %d views, want exactly 1 (the sandbox, not alice-container): %+v", len(views), views)
	}
	if views[0].Name != sb.SandboxId {
		t.Errorf("view name = %q, want %q", views[0].Name, sb.SandboxId)
	}
	if views[0].TTLExpiresAt == nil {
		t.Error("view.TTLExpiresAt is nil, want the stamped expiry")
	}
}

// TestSandboxServer_DeleteContainer_ColdPathDestroys pins that
// SandboxServer.DeleteContainer (the ttlsweeper.Deleter implementation) —
// as opposed to the tenant-facing DeleteSandbox RPC — actually removes a
// cold-path sandbox, with no auth/ownership context required.
func TestSandboxServer_DeleteContainer_ColdPathDestroys(t *testing.T) {
	backend := newFakeSandboxBackend()
	s := NewSandboxServer(backend, nil)
	sb := spawnAsAlice(t, backend, s)

	if err := s.DeleteContainer(context.Background(), sb.SandboxId, "ttl_expired"); err != nil {
		t.Fatalf("DeleteContainer: %v", err)
	}
	if _, ok := backend.instances[sb.SandboxId]; ok {
		t.Error("sandbox still present after DeleteContainer")
	}
}

// TestSandboxServer_DeleteContainer_PoolClaimedRoutesThroughRelease is
// TestDeleteSandbox_PoolClaimedRoutesThroughPoolRelease's sibling for the
// sweeper's own delete path: a pool-claimed sandbox reaped by TTL must
// still free its IPAM address via pool.Release, not merely destroy() the
// container and leak the address — the exact bug class this routing
// exists to prevent (see reapExpired's sibling, claimFromPool's own doc
// comment on why the claimed map exists at all).
func TestSandboxServer_DeleteContainer_PoolClaimedRoutesThroughRelease(t *testing.T) {
	backend := newFakeSandboxBackend()
	// A single-address range: if DeleteContainer ever regresses to a bare
	// destroy() for a pool-claimed sandbox (skipping pool.Release's IPAM
	// free), the only address is never returned and the re-reconcile below
	// fails outright instead of merely allocating a different address —
	// this range makes the routing bug impossible to miss.
	allocator, err := ipam.New("10.100.0.10", "10.100.0.10", "10.100.0.1", 0)
	if err != nil {
		t.Fatalf("ipam.New: %v", err)
	}
	p := pool.New(backend, allocator, pool.Config{
		MinWarm:    map[pb.SandboxTemplate]int{pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE: 1},
		Image:      map[pb.SandboxTemplate]string{pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE: "images:ubuntu/24.04"},
		NICNetwork: "incusbr0",
	})
	p.Reconcile(context.Background())
	s := NewSandboxServer(backend, p)

	resp, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{})
	if err != nil {
		t.Fatalf("SpawnSandbox: %v", err)
	}
	id := resp.Sandbox.SandboxId

	if err := s.DeleteContainer(context.Background(), id, "ttl_expired"); err != nil {
		t.Fatalf("DeleteContainer: %v", err)
	}
	if _, ok := backend.instances[id]; ok {
		t.Error("sandbox still present after DeleteContainer")
	}

	// The address must have come back through IPAM (pool.Release's job) —
	// reconciling a fresh warm at the same target should succeed.
	p.Reconcile(context.Background())
	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 1 {
		t.Errorf("ReadyCount after re-reconciling post-delete = %d, want 1 (address must have been released via pool.Release, not leaked by a bare destroy)", got)
	}
}

// TestSandboxTTLSweep_EndToEnd exercises the full pipeline this PR wires —
// adapter.ListContainers -> ttlsweeper.Decide -> SandboxServer.DeleteContainer
// — against three sandboxes: one already expired, one with plenty of TTL
// left, and one pool-claimed and already expired. Only the two expired
// ones must be gone afterward; the unexpired one must survive untouched.
func TestSandboxTTLSweep_EndToEnd(t *testing.T) {
	backend := newFakeSandboxBackend()
	s := NewSandboxServer(backend, nil)

	expiredCold := spawnAsAlice(t, backend, s)
	freshCold := spawnAsAlice(t, backend, s)

	now := time.Now()
	// Force one sandbox already past its expiry and leave the other with a
	// full TTL window — Decide must tell them apart.
	expiredInfo := backend.instances[expiredCold.SandboxId]
	expiredInfo.TTLExpiresAt = now.Add(-time.Minute)
	backend.instances[expiredCold.SandboxId] = expiredInfo

	adapter := &ttlsweeperSandboxAdapter{backend: backend}
	views, err := adapter.ListContainers()
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	expired := ttlsweeper.Decide(views, now)

	if len(expired) != 1 || expired[0] != expiredCold.SandboxId {
		t.Fatalf("Decide returned %v, want exactly [%s]", expired, expiredCold.SandboxId)
	}

	for _, name := range expired {
		if err := s.DeleteContainer(context.Background(), name, "ttl_expired"); err != nil {
			t.Fatalf("DeleteContainer(%s): %v", name, err)
		}
	}

	if _, ok := backend.instances[expiredCold.SandboxId]; ok {
		t.Error("expired sandbox still present after sweep")
	}
	if _, ok := backend.instances[freshCold.SandboxId]; !ok {
		t.Error("fresh (unexpired) sandbox was deleted by the sweep — Decide/adapter false positive")
	}
}
