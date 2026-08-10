package sentinel

import (
	"errors"
	"runtime"
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

// The `ip` invocation is not exercised by any test that could catch a mistake
// in it: the end-to-end tunnel tests substitute the alias seam, and even
// before they did, they passed on Linux without the alias at all, because
// 127.0.0.0/8 already routes to loopback. A malformed invocation would surface
// on macOS, or on a reconnect against a stale alias — not here.
//
// So the arguments are asserted directly. Cheap, and it covers the failure
// this file's other tests cannot.
func TestLoopbackAliasArgs(t *testing.T) {
	for _, tc := range []struct {
		op   string
		want string
	}{
		{"add", "ip addr add 127.0.0.7/32 dev lo"},
		{"del", "ip addr del 127.0.0.7/32 dev lo"},
	} {
		got := strings.Join(loopbackAliasArgs(tc.op, "127.0.0.7"), " ")
		if got != tc.want {
			t.Errorf("loopbackAliasArgs(%q) = %q, want %q", tc.op, got, tc.want)
		}
	}
}

// The /32 is what keeps the alias a single address. Without it `ip` applies
// the interface default — /8 on loopback — and the alias claims the whole
// 127.0.0.0/8 range, which collides with every other spot's address.
func TestLoopbackAliasIsASingleAddress(t *testing.T) {
	args := loopbackAliasArgs("add", "127.0.0.7")

	var addr string
	for i, a := range args {
		if a == "add" && i+1 < len(args) {
			addr = args[i+1]
		}
	}
	if !strings.HasSuffix(addr, "/32") {
		t.Errorf("alias address = %q, want a /32 — a wider prefix on lo claims every other "+
			"spot's 127.0.0.x address too", addr)
	}
}

// withRecordedIPCmds captures the `ip` invocations instead of running them.
func withRecordedIPCmds(t *testing.T) *[][]string {
	t.Helper()
	var got [][]string
	orig := runIPCmd
	runIPCmd = func(args []string) ([]byte, error) {
		got = append(got, args)
		return nil, nil
	}
	t.Cleanup(func() { runIPCmd = orig })
	return &got
}

// A remove that issued `add` would leak one alias per disconnect, and nothing
// would notice: the callers are only reached through the alias seam the other
// tests substitute, so neither path is otherwise executed at all.
func TestLoopbackAliasCallersIssueTheRightOperation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the alias helpers no-op off Linux, so there is no invocation to record")
	}

	cmds := withRecordedIPCmds(t)
	if err := addLoopbackAlias("127.0.0.7"); err != nil {
		t.Fatalf("add: %v", err)
	}
	removeLoopbackAlias("127.0.0.7")

	if len(*cmds) != 2 {
		t.Fatalf("recorded %d invocations, want 2: %v", len(*cmds), *cmds)
	}
	if got := strings.Join((*cmds)[0], " "); got != "ip addr add 127.0.0.7/32 dev lo" {
		t.Errorf("add issued %q", got)
	}
	if got := strings.Join((*cmds)[1], " "); got != "ip addr del 127.0.0.7/32 dev lo" {
		t.Errorf("remove issued %q — a remove that adds leaks an alias per disconnect until "+
			"the address space runs out", got)
	}
}
