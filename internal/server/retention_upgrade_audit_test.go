package server

import (
	"context"
	"errors"
	"testing"

	"github.com/footprintai/containarium/internal/retention"
)

// upgradeEventStore is a memory store that also holds pending upgrade
// events, like the Postgres store after it clamped or normalised legacy data.
type upgradeEventStore struct {
	*retention.MemoryStore
	pending []retention.UpgradeEvent
}

func (u *upgradeEventStore) AuditUpgradeEvents(_ context.Context, write func(retention.UpgradeEvent) error) (int, error) {
	n := 0
	for len(u.pending) > 0 {
		if err := write(u.pending[0]); err != nil {
			return n, err
		}
		u.pending = u.pending[1:]
		n++
	}
	return n, nil
}

// TestRetentionServer_WiringTheAuditStoreAuditsPendingUpgradeChanges (Q31):
// the changes the store's bootstrap made before any audit store existed are
// written as audit entries by the upgrade actor once one is wired.
func TestRetentionServer_WiringTheAuditStoreAuditsPendingUpgradeChanges(t *testing.T) {
	st := &upgradeEventStore{MemoryStore: retention.NewMemoryStore(), pending: []retention.UpgradeEvent{
		{ID: 1, Action: retention.UpgradeActionClamp, ResourceType: "retention_policy", ResourceID: "cluster", Detail: `{"revision":2}`},
		{ID: 2, Action: retention.UpgradeActionHoldMerge, ResourceType: "legal_hold", ResourceID: "org-b", Detail: `{"held_as":"org-b"}`},
	}}
	s := NewRetentionServer(st)
	a := &fakeAuditLogger{}
	s.SetAuditStore(a)
	if len(a.entries) != 2 || len(st.pending) != 0 {
		t.Fatalf("audit entries = %+v, pending = %+v; want both changes audited", a.entries, st.pending)
	}
	for i, want := range []struct{ action, resType, resID, detail string }{
		{retention.UpgradeActionClamp, "retention_policy", "cluster", `{"revision":2}`},
		{retention.UpgradeActionHoldMerge, "legal_hold", "org-b", `{"held_as":"org-b"}`},
	} {
		e := a.entries[i]
		if e.Username != retention.UpgradeActor || e.Action != want.action || e.ResourceType != want.resType || e.ResourceID != want.resID || e.Detail != want.detail {
			t.Errorf("entry %d = %+v, want %s by %s on %s/%s with %s", i, e, want.action, retention.UpgradeActor, want.resType, want.resID, want.detail)
		}
	}
}

// TestRetentionServer_AFailedUpgradeAuditIsRetriedAtTheNextWiring: a failed
// write does not fail anything else and leaves the change pending.
func TestRetentionServer_AFailedUpgradeAuditIsRetriedAtTheNextWiring(t *testing.T) {
	st := &upgradeEventStore{MemoryStore: retention.NewMemoryStore(), pending: []retention.UpgradeEvent{
		{ID: 1, Action: retention.UpgradeActionClamp, ResourceType: "retention_policy", ResourceID: "cluster", Detail: `{}`},
	}}
	s := NewRetentionServer(st)
	s.SetAuditStore(&fakeAuditLogger{err: errors.New("audit down")})
	if len(st.pending) != 1 {
		t.Fatalf("pending after a failed write = %d, want 1", len(st.pending))
	}
	ok := &fakeAuditLogger{}
	s.SetAuditStore(ok)
	if len(st.pending) != 0 || len(ok.entries) != 1 {
		t.Fatalf("after a working audit store: pending %d, entries %d; want 0 and 1", len(st.pending), len(ok.entries))
	}
}
