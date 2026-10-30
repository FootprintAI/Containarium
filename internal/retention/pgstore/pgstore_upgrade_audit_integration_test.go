//go:build integration

// Q31 on #2727: an upgrade change to stored retention data (a clamped
// window, a normalised, merged or quarantined hold) is recorded in the same
// transaction as the change and audited once an audit store exists; a clamp
// bumps the policy revision.
package pgstore

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/footprintai/containarium/internal/retention"
)

// pendingActions lists the recorded upgrade changes not yet audited.
func pendingActions(t *testing.T, s *Store) []string {
	t.Helper()
	rows, err := s.pool.Query(context.Background(), `SELECT action FROM retention_upgrade_events WHERE audited_at IS NULL ORDER BY id`)
	if err != nil {
		t.Fatalf("read upgrade events: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

// drain audits every pending event into a slice.
func drain(t *testing.T, s *Store) []retention.UpgradeEvent {
	t.Helper()
	var got []retention.UpgradeEvent
	if _, err := s.AuditUpgradeEvents(context.Background(), func(ev retention.UpgradeEvent) error {
		got = append(got, ev)
		return nil
	}); err != nil {
		t.Fatalf("AuditUpgradeEvents: %v", err)
	}
	return got
}

func TestRetentionPGStore_AClampIsRecordedAuditableOnceAndBumpsTheRevision(t *testing.T) {
	ctx := context.Background()
	pool := retentionPool(t)
	createSchema2917(t, pool, `INSERT INTO retention_windows (class, days) VALUES (1, 2000000000), (2, 45);`)
	s := pgStore(t, pool)

	p, err := s.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.GetRevision() != 2 || p.GetUpdatedBy() != retention.UpgradeActor {
		t.Fatalf("policy = revision %d by %q, want revision 2 by %s (the clamp is a policy change)", p.GetRevision(), p.GetUpdatedBy(), retention.UpgradeActor)
	}
	evs := drain(t, s)
	if len(evs) != 1 || evs[0].Action != retention.UpgradeActionClamp || evs[0].ResourceType != "retention_policy" {
		t.Fatalf("events = %+v, want one %s on retention_policy", evs, retention.UpgradeActionClamp)
	}
	var d retention.UpgradeClampDetail
	if err := json.Unmarshal([]byte(evs[0].Detail), &d); err != nil {
		t.Fatalf("clamp detail %q: %v", evs[0].Detail, err)
	}
	want := retention.UpgradeClampedWindow{Class: "RETENTION_CLASS_PROMPTS", StoredDays: 2000000000, Days: retention.MaxDays}
	if d.PreviousRevision != 1 || d.Revision != 2 || len(d.Windows) != 1 || d.Windows[0] != want {
		t.Fatalf("clamp detail = %+v, want revision 1 -> 2 with %+v only", d, want)
	}
	if again := drain(t, s); len(again) != 0 {
		t.Fatalf("a second drain audited %d events again", len(again))
	}
	// A later start finds nothing to change: no new event, no new revision.
	s2 := pgStore(t, pool)
	if p, _ := s2.GetPolicy(ctx); p.GetRevision() != 2 {
		t.Fatalf("revision after a second start = %d, want 2", p.GetRevision())
	}
	if got := pendingActions(t, s2); len(got) != 0 {
		t.Fatalf("a second start recorded %v", got)
	}
}

func TestRetentionPGStore_AFailedAuditWriteLeavesTheEventPending(t *testing.T) {
	pool := retentionPool(t)
	createSchema2917(t, pool, `INSERT INTO retention_windows (class, days) VALUES (1, 2000000000);`)
	s := pgStore(t, pool)
	boom := errors.New("audit down")
	n, err := s.AuditUpgradeEvents(context.Background(), func(retention.UpgradeEvent) error { return boom })
	if !errors.Is(err, boom) || n != 0 {
		t.Fatalf("AuditUpgradeEvents with a failing write = (%d, %v), want (0, the write's error)", n, err)
	}
	if evs := drain(t, s); len(evs) != 1 || evs[0].Action != retention.UpgradeActionClamp {
		t.Fatalf("after a failed write the event must still be pending; drained %+v", evs)
	}
}

func TestRetentionPGStore_HoldUpgradesAreRecordedWithTheStoredHold(t *testing.T) {
	ctx := context.Background()
	pool := retentionPool(t)
	createSchema2917(t, pool, `INSERT INTO retention_legal_holds VALUES
		(' org-a', 'case 1', 'admin-a', NOW() - interval '3 days'),
		('org-b'||chr(9), 'case 2', 'admin-a', NOW() - interval '2 days'),
		('org-b', 'case 3', 'admin-b', NOW() - interval '1 day'),
		('   ', 'case 5', 'admin-c', NOW());`)
	s := pgStore(t, pool)

	byAction := map[string][]retention.UpgradeHoldDetail{}
	for _, ev := range drain(t, s) {
		var d retention.UpgradeHoldDetail
		if err := json.Unmarshal([]byte(ev.Detail), &d); err != nil {
			t.Fatalf("%s detail %q: %v", ev.Action, ev.Detail, err)
		}
		if ev.ResourceType != "legal_hold" || ev.ResourceID != d.HeldAs {
			t.Errorf("%s on %s/%s, want legal_hold/%s", ev.Action, ev.ResourceType, ev.ResourceID, d.HeldAs)
		}
		byAction[ev.Action] = append(byAction[ev.Action], d)
	}
	quarantineID := retention.QuarantineOrgID("   ")
	check := func(action, storedAs, reason, setBy, heldAs string) {
		t.Helper()
		for _, d := range byAction[action] {
			if d.StoredAs.OrgID == storedAs {
				if d.StoredAs.Reason != reason || d.StoredAs.SetBy != setBy || d.HeldAs != heldAs || d.StoredAs.SetAt.IsZero() {
					t.Errorf("%s of %q = %+v, want reason %q, set by %s, held as %q", action, storedAs, d, reason, setBy, heldAs)
				}
				return
			}
		}
		t.Errorf("no %s entry for the hold stored as %q (have %+v)", action, storedAs, byAction)
	}
	check(retention.UpgradeActionHoldNormalise, " org-a", "case 1", "admin-a", "org-a")
	check(retention.UpgradeActionHoldNormalise, "org-b\t", "case 2", "admin-a", "org-b")
	// The later duplicate's reason and setter survive in the record, not only in a log line.
	check(retention.UpgradeActionHoldMerge, "org-b", "case 3", "admin-b", "org-b")
	check(retention.UpgradeActionHoldQuarantine, "   ", "case 5", "admin-c", quarantineID)

	hs, err := s.ListHolds(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, h := range hs {
		ids[h.GetOrgId()] = h.GetReason()
	}
	if len(hs) != 3 || ids["org-a"] != "case 1" || ids["org-b"] != "case 2" || ids[quarantineID] != "case 5" {
		t.Fatalf("holds = %v, want org-a, org-b (the earliest) and the quarantined hold still active", hs)
	}
	if _, err := s.ReleaseHold(ctx, quarantineID, "admin-a", nil); err != nil {
		t.Fatalf("the quarantined hold must be releasable through the API: %v", err)
	}
	if got := pendingActions(t, pgStore(t, pool)); len(got) != 0 {
		t.Fatalf("a second start recorded %v", got)
	}
}
