package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeDenyApplier records AddDeny/DeleteDeny calls and can be told to fail an
// AddDeny for a given key, so applyDeny's apply/retry semantics are testable
// without a kernel.
type fakeDenyApplier struct {
	added   []netbpf.DenyEntry
	deleted []netbpf.DenyKey
	failAdd map[netbpf.DenyKey]bool
}

func (f *fakeDenyApplier) AddDeny(e netbpf.DenyEntry) error {
	if f.failAdd[e.Key()] {
		return fmt.Errorf("inject add failure")
	}
	f.added = append(f.added, e)
	return nil
}

func (f *fakeDenyApplier) DeleteDeny(k netbpf.DenyKey) error {
	f.deleted = append(f.deleted, k)
	return nil
}

func TestPlanReconcile_DenyRules(t *testing.T) {
	policies := map[string]netpolicy.CompiledPolicy{
		"alice": compiled(t, &pb.NetworkPolicy{
			Tenant:      "alice",
			EgressCidrs: []string{"8.8.8.8/32"},
			DenyRules: []*pb.NetworkPolicyDenyRule{
				{Cidr: "1.2.3.4/32", Port: 6379, Proto: "tcp", Note: "CVE-x"},
			},
		}),
	}
	views := []containerView{
		{Name: "alice-container", Tenant: "alice", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true},
		// second alice container — deny emitted once per tenant, like egress.
		{Name: "alice-web-container", Tenant: "alice", TenantID: 1, Ifindex: 12, HasVeth: true, Running: true},
	}

	plan := planReconcile(views, policies, true)

	if len(plan.deny) != 1 {
		t.Fatalf("deny size = %d, want 1 (once per tenant): %+v", len(plan.deny), plan.deny)
	}
	d := plan.deny[0]
	want := netbpf.DenyEntry{PrefixLen: 64, TenantID: 1, Addr: [4]byte{1, 2, 3, 4}, Port: 6379, Proto: 6}
	if d != want {
		t.Errorf("deny entry = %+v, want %+v", d, want)
	}
}

func TestDiffDeny(t *testing.T) {
	// a and a2 share a CIDR key but differ in port (value) → a2 is an upsert, not
	// an add+delete of two slots.
	a := netbpf.DenyEntry{PrefixLen: 64, TenantID: 1, Addr: [4]byte{1, 2, 3, 4}, Port: 80}
	a2 := netbpf.DenyEntry{PrefixLen: 64, TenantID: 1, Addr: [4]byte{1, 2, 3, 4}, Port: 443}
	b := netbpf.DenyEntry{PrefixLen: 40, TenantID: 2, Addr: [4]byte{10, 0, 0, 0}}

	installed := map[netbpf.DenyKey]netbpf.DenyEntry{a.Key(): a, b.Key(): b}
	desired := []netbpf.DenyEntry{a2} // change a's port, drop b

	upsert, del := diffDeny(installed, desired)
	if len(upsert) != 1 || upsert[0] != a2 {
		t.Errorf("upsert = %+v, want [a2]", upsert)
	}
	if len(del) != 1 || del[0] != b.Key() {
		t.Errorf("del = %+v, want [b.Key()]", del)
	}
	// a2's key equals a's key, so it must NOT appear in the delete set (that would
	// drop the entry we just upserted).
	for _, k := range del {
		if k == a2.Key() {
			t.Error("changed-port rule must be an upsert, not a delete of its own key")
		}
	}

	// Converged → no churn.
	up2, del2 := diffDeny(map[netbpf.DenyKey]netbpf.DenyEntry{a2.Key(): a2}, []netbpf.DenyEntry{a2})
	if len(up2) != 0 || len(del2) != 0 {
		t.Errorf("converged diff should be empty, got upsert=%v del=%v", up2, del2)
	}
}

func TestApplyDeny(t *testing.T) {
	a := netbpf.DenyEntry{PrefixLen: 64, TenantID: 1, Addr: [4]byte{1, 2, 3, 4}, Port: 80}
	a2 := netbpf.DenyEntry{PrefixLen: 64, TenantID: 1, Addr: [4]byte{1, 2, 3, 4}, Port: 443} // same key as a
	b := netbpf.DenyEntry{PrefixLen: 40, TenantID: 2, Addr: [4]byte{10, 0, 0, 0}}

	t.Run("fresh install adds all and records them", func(t *testing.T) {
		installed := map[netbpf.DenyKey]netbpf.DenyEntry{}
		f := &fakeDenyApplier{}
		applyDeny(installed, []netbpf.DenyEntry{a, b}, f)
		if len(f.added) != 2 || len(f.deleted) != 0 {
			t.Fatalf("added=%v deleted=%v, want 2 added / 0 deleted", f.added, f.deleted)
		}
		if installed[a.Key()] != a || installed[b.Key()] != b {
			t.Errorf("installed not recorded: %+v", installed)
		}
	})

	t.Run("port-only change is one upsert of the same slot, never a delete", func(t *testing.T) {
		installed := map[netbpf.DenyKey]netbpf.DenyEntry{a.Key(): a}
		f := &fakeDenyApplier{}
		applyDeny(installed, []netbpf.DenyEntry{a2}, f)
		if len(f.added) != 1 || f.added[0] != a2 {
			t.Errorf("added=%v, want [a2] (upsert)", f.added)
		}
		if len(f.deleted) != 0 {
			t.Fatalf("deleted=%v, want none — the changed-port rule shares a's key", f.deleted)
		}
		if installed[a.Key()] != a2 {
			t.Errorf("installed[key] = %+v, want a2", installed[a.Key()])
		}
	})

	t.Run("removal deletes the stale key and drops it from installed", func(t *testing.T) {
		installed := map[netbpf.DenyKey]netbpf.DenyEntry{a.Key(): a, b.Key(): b}
		f := &fakeDenyApplier{}
		applyDeny(installed, []netbpf.DenyEntry{a}, f)
		if len(f.deleted) != 1 || f.deleted[0] != b.Key() {
			t.Errorf("deleted=%v, want [b.Key()]", f.deleted)
		}
		if _, ok := installed[b.Key()]; ok {
			t.Error("b should be gone from installed")
		}
	})

	t.Run("a failed add is not recorded so the next reconcile retries", func(t *testing.T) {
		installed := map[netbpf.DenyKey]netbpf.DenyEntry{}
		f := &fakeDenyApplier{failAdd: map[netbpf.DenyKey]bool{a.Key(): true}}
		applyDeny(installed, []netbpf.DenyEntry{a, b}, f)
		if _, ok := installed[a.Key()]; ok {
			t.Error("failed add must NOT be recorded in installed (else the kernel and bookkeeping diverge)")
		}
		if installed[b.Key()] != b {
			t.Error("b should still install despite a's failure")
		}
		// Next pass with the failure cleared converges a.
		f.failAdd = nil
		applyDeny(installed, []netbpf.DenyEntry{a, b}, f)
		if installed[a.Key()] != a {
			t.Error("retry should install a once the failure clears")
		}
	})

	t.Run("converged state is a no-op", func(t *testing.T) {
		installed := map[netbpf.DenyKey]netbpf.DenyEntry{a.Key(): a, b.Key(): b}
		f := &fakeDenyApplier{}
		applyDeny(installed, []netbpf.DenyEntry{a, b}, f)
		if len(f.added) != 0 || len(f.deleted) != 0 {
			t.Errorf("converged apply should do nothing, got added=%v deleted=%v", f.added, f.deleted)
		}
	})
}

func TestActiveDenyRules(t *testing.T) {
	now := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	rules := []netpolicy.DenyRule{
		{Note: "live", ExpiresAt: now.Add(time.Hour)},
		{Note: "expired", ExpiresAt: now.Add(-time.Hour)},
		{Note: "permanent"}, // zero expiry
	}
	got := activeDenyRules(rules, now)
	if len(got) != 2 {
		t.Fatalf("want 2 active rules, got %d: %+v", len(got), got)
	}
	for _, r := range got {
		if r.Note == "expired" {
			t.Error("expired rule should have been dropped")
		}
	}
}
