package sentinel

import (
	"errors"
	"strings"
	"testing"
)

// #1139: after a backend is down for a long stretch and returns on the same
// internal IP, the sentinel could keep stale upstream forwarding state until
// an operator restarted the service by hand.
//
// One concrete gap in that class: the reconnect path reused the recorded
// loopback IP without re-asserting it on `lo`. Reusing an address is not the
// same as the address still existing — the registry's map outlives the alias
// across a host network reconfiguration or an `ip addr flush` — and nothing
// else re-adds it, so forwarding points at an address the kernel no longer
// has.

// aliasRecorder counts alias adds so a test can see whether reconnect
// re-asserted one.
type aliasRecorder struct {
	added   []string
	removed []string
	err     error
}

func (a *aliasRecorder) add(ip string) error {
	if a.err != nil {
		return a.err
	}
	a.added = append(a.added, ip)
	return nil
}

func (a *aliasRecorder) remove(ip string) {
	a.removed = append(a.removed, ip)
}

// withRecordedAliases swaps in the recorder for the duration of a test.
func withRecordedAliases(t *testing.T) *aliasRecorder {
	t.Helper()
	rec := &aliasRecorder{}
	origAdd, origRemove := addLoopbackAliasFn, removeLoopbackAliasFn
	addLoopbackAliasFn, removeLoopbackAliasFn = rec.add, rec.remove
	t.Cleanup(func() { addLoopbackAliasFn, removeLoopbackAliasFn = origAdd, origRemove })
	return rec
}

func TestRegister_ReassertsLoopbackAliasOnReconnect(t *testing.T) {
	rec := withRecordedAliases(t)
	r := NewTunnelRegistry()

	ip1, _, err := r.Register(&TunnelHandshake{SpotID: "spot-a"}, nil)
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if len(rec.added) != 1 {
		t.Fatalf("first registration added %d aliases, want 1", len(rec.added))
	}

	// The backend returns after a long outage and re-registers under the same
	// spot ID — the reconnect path.
	ip2, _, err := r.Register(&TunnelHandshake{SpotID: "spot-a"}, nil)
	if err != nil {
		t.Fatalf("reconnect Register: %v", err)
	}

	if ip2 != ip1 {
		t.Errorf("reconnect moved the spot from %s to %s; the IP must be stable so sshpiper's "+
			"config does not go stale", ip1, ip2)
	}
	if len(rec.added) != 2 {
		t.Errorf("reconnect added %d aliases in total, want 2 — the alias was not re-asserted, so "+
			"a spot whose loopback address had gone would keep forwarding to an IP the kernel no "+
			"longer has, recoverable only by restarting the sentinel (#1139)", len(rec.added))
	}
	if len(rec.added) == 2 && rec.added[1] != ip1 {
		t.Errorf("re-asserted %s, want the spot's own %s", rec.added[1], ip1)
	}
}

// A genuinely failing alias add on reconnect must fail the registration
// rather than returning a spot that cannot be routed to. "Already exists" is
// NOT such a failure — addLoopbackAlias absorbs it — so this only fires for
// real errors.
func TestRegister_ReconnectFailsWhenTheAliasCannotBeRestored(t *testing.T) {
	rec := withRecordedAliases(t)
	r := NewTunnelRegistry()

	if _, _, err := r.Register(&TunnelHandshake{SpotID: "spot-a"}, nil); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	rec.err = errors.New("RTNETLINK answers: Operation not permitted")
	_, _, err := r.Register(&TunnelHandshake{SpotID: "spot-a"}, nil)
	if err == nil {
		t.Fatal("reconnect succeeded though the loopback alias could not be restored — the spot " +
			"would be registered and unroutable, which is the silent half of this failure")
	}
	if !strings.Contains(err.Error(), "reconnect") {
		t.Errorf("error should say the failure was on the reconnect path, got %v", err)
	}
}

// The fresh-allocation path is unchanged: exactly one alias add, and a
// failure there still aborts.
func TestRegister_FirstRegistrationUnchanged(t *testing.T) {
	rec := withRecordedAliases(t)
	r := NewTunnelRegistry()

	if _, _, err := r.Register(&TunnelHandshake{SpotID: "spot-a"}, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(rec.added) != 1 {
		t.Errorf("first registration added %d aliases, want exactly 1", len(rec.added))
	}
}
