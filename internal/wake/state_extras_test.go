package wake

import (
	"testing"
)

// TestWakeStateTracker_Snapshot_IsACopy — mutating the returned map
// must not leak into the tracker. The brief flagged this because some
// implementations return the live map by reference and confuse callers
// that iterate while writers race.
func TestWakeStateTracker_Snapshot_IsACopy(t *testing.T) {
	tracker := New()
	tracker.MarkWakeMode("alice-container", "alice.example.test", "10.0.3.1", 8080)
	snap := tracker.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot len = %d, want 1", len(snap))
	}
	// Mutate the snapshot.
	delete(snap, "alice-container")
	snap["bogus"] = WakeEntry{Subdomain: "bogus", WakeHost: "0.0.0.0"}

	// Tracker should still hold alice-container and not bogus.
	if _, _, ok := tracker.IsInWakeMode("alice-container"); !ok {
		t.Errorf("alice-container should still be in wake mode (snapshot was mutated)")
	}
	if _, _, ok := tracker.IsInWakeMode("bogus"); ok {
		t.Errorf("bogus should not be in wake mode (snapshot was mutated)")
	}
}

// TestWakeStateTracker_Entry — Entry(name) returns the full WakeEntry;
// unknown name returns the zero value + ok=false.
func TestWakeStateTracker_Entry(t *testing.T) {
	tracker := New()
	tracker.MarkWakeMode("alice-container", "alice.example.test", "10.0.3.1", 8080)

	got, ok := tracker.Entry("alice-container")
	if !ok {
		t.Fatal("alice-container should be present")
	}
	if got.Subdomain != "alice.example.test" || got.WakeHost != "10.0.3.1" || got.WakePort != 8080 {
		t.Errorf("entry = %+v, want full WakeEntry", got)
	}

	zero, ok := tracker.Entry("does-not-exist")
	if ok {
		t.Errorf("Entry(missing) ok = true, want false")
	}
	if zero != (WakeEntry{}) {
		t.Errorf("Entry(missing) = %+v, want zero value", zero)
	}
}

// TestWakeStateTracker_IsInWakeMode_HostAndPort — the (host, port, ok)
// triple matches what was passed to MarkWakeMode. Locks the return
// shape because RouteSyncJob (in package app) depends on it.
func TestWakeStateTracker_IsInWakeMode_HostAndPort(t *testing.T) {
	tracker := New()
	tracker.MarkWakeMode("alice-container", "alice.example.test", "10.0.3.7", 8443)
	host, port, ok := tracker.IsInWakeMode("alice-container")
	if !ok {
		t.Fatal("expected ok=true for marked container")
	}
	if host != "10.0.3.7" {
		t.Errorf("host = %q, want 10.0.3.7", host)
	}
	if port != 8443 {
		t.Errorf("port = %d, want 8443", port)
	}

	host, port, ok = tracker.IsInWakeMode("missing")
	if ok {
		t.Errorf("missing container ok = true, want false")
	}
	if host != "" || port != 0 {
		t.Errorf("missing container = (%q,%d), want empty", host, port)
	}
}
