package sshgate

import (
	"testing"
	"time"
)

// TestClientCredentialFailureRetainsRiskWithoutOutage protects pass-through passwords.
func TestClientCredentialFailureRetainsRiskWithoutOutage(t *testing.T) {
	f := newGateFixture(t, func(p *Policy) { p.Budget = 2 })
	if !f.g.Complete(f.take(t, 1), ClientAuthRejected) {
		t.Fatal("client denial was not settled")
	}
	l := f.take(t, 1)
	if l.Probe {
		t.Fatal("bad client credential declared a backend outage")
	}
	denied(t, f.g, f.key, 1, 1, BudgetExhausted)
	f.g.Complete(l, SetupSucceeded)
	denied(t, f.g, f.key, 1, 2, BudgetExhausted)
}

// TestCheckpointRetainsPendingRiskAndExclusion does not trust a lost setup as ready.
func TestCheckpointRetainsPendingRiskAndExclusion(t *testing.T) {
	f := newGateFixture(t, func(p *Policy) { p.Budget = 3 })
	start := f.now
	f.g.Complete(f.take(t, 1), ProxyAuthRejected)
	f.g.HintRecovery(f.key, 1)
	old := f.take(t, 2)
	rows := f.g.Checkpoint()
	if len(rows) != 1 || len(rows[0].Risks) != 2 {
		t.Fatalf("lost retained or pending risk: %+v", rows)
	}
	fresh := newGateFixture(t, func(p *Policy) { p.Budget = 3 })
	// Restore is intentionally only permitted before inventory is registered.
	g, err := New(fresh.g.policy, func() time.Time { return f.now }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Restore(rows); err != nil {
		t.Fatal(err)
	}
	if g.Complete(old, SetupSucceeded) {
		t.Fatal("old-process completion reopened restored state")
	}
	denied(t, g, f.key, 1, 1, Cooldown)
	f.now = start.Add(time.Minute)
	probe, err := g.Acquire(f.key, 1, 1)
	if err != nil || !probe.Probe {
		t.Fatalf("first elapsed charge did not release one safe probe: %v", err)
	}
	g.Complete(probe, SetupSucceeded)
	denied(t, g, f.key, 1, 2, BudgetExhausted)
	f.now = old.Deadline.Add(time.Minute)
	if _, err := g.Acquire(f.key, 1, 2); err != nil {
		t.Fatal(err)
	}
}

// TestRestoreRejectsCorruptStateAtomically refuses risk loss or partial restoration.
func TestRestoreRejectsCorruptStateAtomically(t *testing.T) {
	f := newGateFixture(t)
	f.g.Complete(f.take(t, 1), SetupFailed)
	rows := f.g.Checkpoint()
	if len(rows) != 1 || len(rows[0].Risks) != 1 {
		t.Fatal("checkpoint omitted the retained failure")
	}
	for _, corrupt := range []func([]State){
		func(s []State) { s[0].Key.Backend = "" },
		func(s []State) { s[0].Route = 0 },
		func(s []State) { s[0].Risks[0].Cost = 0 },
		func(s []State) { s[0].Risks[0].Cost = 9 },
		func(s []State) { s[0].Risks[0].At = time.Time{} },
	} {
		copyRows := append([]State(nil), rows...)
		copyRows[0].Risks = append([]Risk(nil), rows[0].Risks...)
		corrupt(copyRows)
		g, err := New(f.g.policy, func() time.Time { return f.now }, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := g.Restore(copyRows); err == nil {
			t.Fatal("accepted malformed checkpoint")
		}
		denied(t, g, f.key, 1, 1, UnknownBackend)
	}
}
