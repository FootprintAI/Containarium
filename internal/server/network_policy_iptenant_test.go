package server

import (
	"fmt"
	"sort"
	"testing"
)

// fakeIPTenantApplier records SetIPTenant/DeleteIPTenant calls and can be told
// to fail a Set for a given IP, so applyIPTenant's apply/retry semantics are
// testable without a kernel.
type fakeIPTenantApplier struct {
	set     map[[4]byte]uint32
	deleted [][4]byte
	failSet map[[4]byte]bool
}

func newFakeIPTenantApplier() *fakeIPTenantApplier {
	return &fakeIPTenantApplier{set: map[[4]byte]uint32{}, failSet: map[[4]byte]bool{}}
}

func (f *fakeIPTenantApplier) SetIPTenant(ip [4]byte, tid uint32) error {
	if f.failSet[ip] {
		return fmt.Errorf("inject set failure")
	}
	f.set[ip] = tid
	return nil
}

func (f *fakeIPTenantApplier) DeleteIPTenant(ip [4]byte) error {
	f.deleted = append(f.deleted, ip)
	return nil
}

func TestDiffIPTenant(t *testing.T) {
	a := [4]byte{10, 0, 3, 1}
	b := [4]byte{10, 0, 3, 2}
	c := [4]byte{10, 0, 3, 3}

	installed := map[[4]byte]uint32{
		a: 1, // unchanged
		b: 1, // tenant changes to 2 -> re-set
		c: 1, // no longer desired -> delete
	}
	desired := map[[4]byte]uint32{
		a: 1,
		b: 2,
	}

	set, del := diffIPTenant(installed, desired)

	if got, ok := set[b]; !ok || got != 2 {
		t.Errorf("b should be re-set to tenant 2, got set=%v", set)
	}
	if _, ok := set[a]; ok {
		t.Errorf("a is unchanged and must not be re-set, got set=%v", set)
	}
	if len(del) != 1 || del[0] != c {
		t.Errorf("only c should be deleted, got del=%v", del)
	}
}

// The regression this guards (#923): a tag whose container is gone (or whose
// entity is excluded from tagging, e.g. the control plane) must be DELETED, not
// left behind. The old add-only reconcile leaked it until a daemon restart.
func TestApplyIPTenant_DeletesStaleTag(t *testing.T) {
	cp := [4]byte{10, 0, 3, 241}   // e.g. the control-plane IP, now excluded
	tenant := [4]byte{10, 0, 3, 7} // a live tenant container

	installed := map[[4]byte]uint32{cp: 9, tenant: 1}
	desired := map[[4]byte]uint32{tenant: 1} // cp no longer tagged

	f := newFakeIPTenantApplier()
	applyIPTenant(installed, desired, f)

	if len(f.deleted) != 1 || f.deleted[0] != cp {
		t.Fatalf("stale CP tag should be deleted, got deleted=%v", f.deleted)
	}
	if _, ok := installed[cp]; ok {
		t.Errorf("installed must drop the deleted key, still has %v", cp)
	}
	if installed[tenant] != 1 {
		t.Errorf("live tenant tag must survive, installed=%v", installed)
	}
}

func TestApplyIPTenant_RetriesOnSetFailure(t *testing.T) {
	ip := [4]byte{10, 0, 3, 5}
	installed := map[[4]byte]uint32{}
	desired := map[[4]byte]uint32{ip: 3}

	f := newFakeIPTenantApplier()
	f.failSet[ip] = true
	applyIPTenant(installed, desired, f)

	// A failed set must NOT be recorded as installed, so the next reconcile retries.
	if _, ok := installed[ip]; ok {
		t.Errorf("failed set must not be marked installed, installed=%v", installed)
	}

	// Next cycle succeeds -> now recorded.
	f.failSet[ip] = false
	applyIPTenant(installed, desired, f)
	if installed[ip] != 3 {
		t.Errorf("retry should install the tag, installed=%v", installed)
	}
}

func TestApplyIPTenant_ConvergesToEmpty(t *testing.T) {
	x := [4]byte{10, 0, 3, 8}
	y := [4]byte{10, 0, 3, 9}
	installed := map[[4]byte]uint32{x: 1, y: 2}

	f := newFakeIPTenantApplier()
	applyIPTenant(installed, map[[4]byte]uint32{}, f) // all containers gone

	sort.Slice(f.deleted, func(i, j int) bool { return f.deleted[i][3] < f.deleted[j][3] })
	if len(f.deleted) != 2 || f.deleted[0] != x || f.deleted[1] != y {
		t.Errorf("both stale tags should be deleted, got %v", f.deleted)
	}
	if len(installed) != 0 {
		t.Errorf("installed should be empty after full drain, got %v", installed)
	}
}
