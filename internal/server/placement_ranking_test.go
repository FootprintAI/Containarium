package server

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// known builds a PeerClient with a known committed/physical capacity.
func known(id, pool string, committed, physical float64) *PeerClient {
	return &PeerClient{
		ID: id, Pool: pool, Healthy: true,
		CachedCommittedCores: committed, CachedPhysicalCores: physical, CapacityKnown: true,
	}
}

// TestLeastCommitted pins the ranking: lowest known overcommit ratio wins;
// unknown-capacity peers rank after every known one; ties break by ID so the
// choice is deterministic rather than map-order-arbitrary.
func TestLeastCommitted(t *testing.T) {
	t.Run("nil for empty", func(t *testing.T) {
		if leastCommitted(nil) != nil {
			t.Fatal("want nil for no candidates")
		}
	})

	t.Run("lowest ratio wins across different host sizes", func(t *testing.T) {
		// 8-core host at 6 committed = 0.75; 32-core host at 10 = 0.31.
		small := known("small", "p", 6, 8)
		big := known("big", "p", 10, 32)
		if got := leastCommitted([]*PeerClient{small, big}); got != big {
			t.Fatalf("want big (ratio 0.31), got %s", got.ID)
		}
	})

	t.Run("known beats unknown even when known is busier", func(t *testing.T) {
		busy := known("busy", "p", 30, 8) // 3.75x — but we KNOW it
		unknown := &PeerClient{ID: "mystery", Pool: "p", Healthy: true}
		if got := leastCommitted([]*PeerClient{unknown, busy}); got != busy {
			t.Fatalf("want busy (known), got %s", got.ID)
		}
	})

	t.Run("two unknowns break by ID", func(t *testing.T) {
		a := &PeerClient{ID: "aaa", Pool: "p", Healthy: true}
		b := &PeerClient{ID: "bbb", Pool: "p", Healthy: true}
		if got := leastCommitted([]*PeerClient{b, a}); got != a {
			t.Fatalf("want aaa (ID tie-break), got %s", got.ID)
		}
	})

	t.Run("equal ratio breaks by ID", func(t *testing.T) {
		z := known("zzz", "p", 4, 8)  // 0.5
		a := known("aaa", "p", 8, 16) // 0.5
		if got := leastCommitted([]*PeerClient{z, a}); got != a {
			t.Fatalf("want aaa (ID tie-break at equal ratio), got %s", got.ID)
		}
	})

	t.Run("physical<=0 is treated as unknown", func(t *testing.T) {
		bogus := &PeerClient{ID: "bogus", Pool: "p", Healthy: true, CapacityKnown: true, CachedPhysicalCores: 0, CachedCommittedCores: 4}
		real := known("real", "p", 7, 8) // 0.875, known
		if got := leastCommitted([]*PeerClient{bogus, real}); got != real {
			t.Fatalf("want real (bogus has no physical cores), got %s", got.ID)
		}
	})
}

// TestPickLeastCommittedInPool: the pool method filters to healthy peers in the
// named pool before ranking.
func TestPickLeastCommittedInPool(t *testing.T) {
	p := NewPeerPool("local-prod", "", nil, "prod")
	p.peers["idle-demo"] = known("idle-demo", "demo", 2, 8) // 0.25
	p.peers["busy-demo"] = known("busy-demo", "demo", 7, 8) // 0.875
	p.peers["idle-lab"] = known("idle-lab", "lab", 0, 8)    // other pool
	p.peers["down-demo"] = known("down-demo", "demo", 0, 8) // idlest but unhealthy
	p.peers["down-demo"].Healthy = false

	got := p.PickLeastCommittedInPool("demo")
	if got == nil || got.ID != "idle-demo" {
		t.Fatalf("want idle-demo, got %v", got)
	}
	if p.PickLeastCommittedInPool("nonexistent") != nil {
		t.Fatal("want nil for a pool with no healthy peers")
	}
}

// TestResolvePoolPlacement_CapacityRanking: with ranking enabled,
// resolvePoolPlacement routes to the least-committed peer; with it off, it
// keeps first-healthy behavior. Local is out of the target pool here so the
// peer path is exercised.
func TestResolvePoolPlacement_CapacityRanking(t *testing.T) {
	newPool := func() *PeerPool {
		p := NewPeerPool("local-prod", "", nil, "prod")
		p.peers["busy"] = known("busy", "demo", 7, 8)
		p.peers["idle"] = known("idle", "demo", 1, 8)
		return p
	}

	t.Run("ranking on: least-committed wins", func(t *testing.T) {
		p := newPool()
		p.EnableCapacityRanking(func() (string, error) { return "service-token", nil })
		s := &ContainerServer{peerPool: p}
		req := &pb.CreateContainerRequest{Pool: "demo"}
		if err := s.resolvePoolPlacement(req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.BackendId != "idle" {
			t.Fatalf("want idle, got %q", req.BackendId)
		}
	})

	t.Run("ranking off: unchanged first-healthy path", func(t *testing.T) {
		p := newPool() // ranking not enabled
		s := &ContainerServer{peerPool: p}
		if p.CapacityRankingEnabled() {
			t.Fatal("ranking should be off")
		}
		req := &pb.CreateContainerRequest{Pool: "demo"}
		if err := s.resolvePoolPlacement(req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// first-healthy is map-order-arbitrary; just assert it picked one.
		if req.BackendId != "idle" && req.BackendId != "busy" {
			t.Fatalf("want a demo peer, got %q", req.BackendId)
		}
	})

	t.Run("ranking on but no healthy peer errors", func(t *testing.T) {
		p := NewPeerPool("local-prod", "", nil, "prod")
		p.EnableCapacityRanking(func() (string, error) { return "service-token", nil })
		s := &ContainerServer{peerPool: p}
		req := &pb.CreateContainerRequest{Pool: "demo"}
		if err := s.resolvePoolPlacement(req); err == nil {
			t.Fatal("want error when no healthy peer in pool")
		}
	})
}

// TestEnableCapacityRanking_NilTokenNoop: a nil token provider must not flip
// ranking on (we'd fetch nothing and rank on always-unknown capacity).
func TestEnableCapacityRanking_NilTokenNoop(t *testing.T) {
	p := NewPeerPool("local", "", nil, "prod")
	p.EnableCapacityRanking(nil)
	if p.CapacityRankingEnabled() {
		t.Fatal("empty token must leave ranking off")
	}
}
