package cluster

// SetNodeGroupTarget (#1882). The both-impls round-trip lives in the
// tagged store_integration_test.go; this is the untagged half so the
// fast lane also fails when a concurrent caller for one group can
// clobber a different group's already-committed target.

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func newTestCluster(t *testing.T, s *MemStore, owner, name string, groups []NodeGroup) {
	t.Helper()
	ctx := context.Background()
	if err := s.Create(ctx, &Cluster{
		ID: uuid.NewString(), Owner: owner, Name: name,
		State: StateProvisioning, NodeGroups: groups,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
}

// TestSetNodeGroupTarget_OnlyTouchesTheNamedGroup pins the property
// that makes a concurrent call for a different group safe: this call
// has no externally-held snapshot of the OTHER groups to carry
// forward, so there is nothing for it to clobber them with.
func TestSetNodeGroupTarget_OnlyTouchesTheNamedGroup(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()
	newTestCluster(t, s, "e2etenant", "lane", []NodeGroup{
		{Name: "small", MinNodes: 1, MaxNodes: 3, TargetNodes: 1},
		{Name: "medium", MinNodes: 0, MaxNodes: 2, TargetNodes: 1},
	})

	if err := s.SetNodeGroupTarget(ctx, "e2etenant", "lane", "medium", 0); err != nil {
		t.Fatalf("SetNodeGroupTarget: %v", err)
	}

	got, err := s.Get(ctx, "e2etenant", "lane")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for _, g := range got.NodeGroups {
		switch g.Name {
		case "medium":
			if g.TargetNodes != 0 {
				t.Errorf("medium.TargetNodes = %d, want 0", g.TargetNodes)
			}
		case "small":
			if g.TargetNodes != 1 {
				t.Errorf("small.TargetNodes = %d, want 1 (untouched)", g.TargetNodes)
			}
		}
	}
}

// TestSetNodeGroupTarget_ConcurrentDifferentGroupsBothStick reproduces
// #1882 live: the autoscaler processing "small"'s and "medium"'s
// scale-down in the same window drives two concurrent
// NodeGroupDeleteNodes calls, one per group, against the same
// cluster. The old setTarget read the whole NodeGroups array, changed
// one group's TargetNodes in a local copy, and wrote the whole array
// back — whichever call's Get() ran before the OTHER's write
// committed carried a stale copy of it forward, and overwrote it when
// it wrote last. Observed live: "medium" was correctly scaled to 0
// and its node deleted, then the reconciler recreated it on its very
// next 15s tick because a concurrent "small" update had written
// medium's TargetNodes back to 1.
//
// SetNodeGroupTarget removes the shared, externally-held snapshot
// this race needed — every one of many concurrent runs must land both
// groups' final values, never lose one to the other.
func TestSetNodeGroupTarget_ConcurrentDifferentGroupsBothStick(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()
	newTestCluster(t, s, "e2etenant", "lane", []NodeGroup{
		{Name: "small", MinNodes: 1, MaxNodes: 3, TargetNodes: 2},
		{Name: "medium", MinNodes: 0, MaxNodes: 2, TargetNodes: 1},
	})

	const rounds = 200
	for i := 0; i < rounds; i++ {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := s.SetNodeGroupTarget(ctx, "e2etenant", "lane", "small", 1); err != nil {
				t.Errorf("round %d: SetNodeGroupTarget(small): %v", i, err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := s.SetNodeGroupTarget(ctx, "e2etenant", "lane", "medium", 0); err != nil {
				t.Errorf("round %d: SetNodeGroupTarget(medium): %v", i, err)
			}
		}()
		wg.Wait()

		got, err := s.Get(ctx, "e2etenant", "lane")
		if err != nil {
			t.Fatalf("round %d: Get: %v", i, err)
		}
		for _, g := range got.NodeGroups {
			switch g.Name {
			case "small":
				if g.TargetNodes != 1 {
					t.Fatalf("round %d: small.TargetNodes = %d, want 1 (clobbered by the concurrent medium update)", i, g.TargetNodes)
				}
			case "medium":
				if g.TargetNodes != 0 {
					t.Fatalf("round %d: medium.TargetNodes = %d, want 0 (clobbered by the concurrent small update)", i, g.TargetNodes)
				}
			}
		}
		// Reset for the next round so a real regression can't hide
		// behind "already at the target from last round".
		if err := s.SetNodeGroupTarget(ctx, "e2etenant", "lane", "small", 2); err != nil {
			t.Fatalf("round %d: reset small: %v", i, err)
		}
		if err := s.SetNodeGroupTarget(ctx, "e2etenant", "lane", "medium", 1); err != nil {
			t.Fatalf("round %d: reset medium: %v", i, err)
		}
	}
}
