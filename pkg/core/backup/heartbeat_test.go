package backup

import (
	"testing"
	"time"
)

// tickingClock returns a clock func that advances by step on every call,
// starting at start — lets a test seed several backups with distinct,
// known-ordered timestamps without sleeping.
func tickingClock(start time.Time, step time.Duration) func() time.Time {
	t := start
	return func() time.Time {
		cur := t
		t = t.Add(step)
		return cur
	}
}

// OSS #2294: the metrics-export heartbeat reads this at every export tick
// to compute "seconds since last successful backup" per tenant — it must
// reflect the MOST RECENT backup, not the first or an arbitrary one, and
// must never conflate one tenant's history with another's.
func TestLastSuccessByUsername_ReturnsMostRecentPerTenant(t *testing.T) {
	ops := newFakeOps([]byte("PGDMP\x00archive"))
	m := newTestManager(t, ops)
	m.clock = tickingClock(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Hour)

	// alice: two backups, an hour apart — the SECOND (later) one must win.
	if _, err := m.Create(CreateOptions{Username: "alice", ContainerName: "c", Conn: PgConn{Database: "app"}, Destination: DestLocal}); err != nil {
		t.Fatal(err)
	}
	aliceSecond, err := m.Create(CreateOptions{Username: "alice", ContainerName: "c", Conn: PgConn{Database: "app"}, Destination: DestLocal})
	if err != nil {
		t.Fatal(err)
	}
	// bob: one backup, in between alice's two (by clock order) — must not
	// pick up either of alice's timestamps.
	bob, err := m.Create(CreateOptions{Username: "bob", ContainerName: "c2", Conn: PgConn{Database: "app"}, Destination: DestLocal})
	if err != nil {
		t.Fatal(err)
	}

	got, err := m.LastSuccessByUsername()
	if err != nil {
		t.Fatalf("LastSuccessByUsername: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d tenants, want 2: %+v", len(got), got)
	}
	if !got["alice"].Equal(aliceSecond.CreatedAt) {
		t.Errorf("alice = %v, want her later backup's CreatedAt %v", got["alice"], aliceSecond.CreatedAt)
	}
	if !got["bob"].Equal(bob.CreatedAt) {
		t.Errorf("bob = %v, want %v", got["bob"], bob.CreatedAt)
	}
}

// A tenant with zero stored backups has nothing to report an age
// against — absent from the map, not a zero-value time.Time (which would
// read as "last success in 0001" and immediately trip any sane alert
// threshold for a tenant that was simply never backed up in the first
// place).
func TestLastSuccessByUsername_NoBackupsIsEmptyMap(t *testing.T) {
	ops := newFakeOps([]byte("PGDMP\x00archive"))
	m := newTestManager(t, ops)

	got, err := m.LastSuccessByUsername()
	if err != nil {
		t.Fatalf("LastSuccessByUsername: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v, want empty map", got)
	}
}
