package sshban

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const mainListener = pb.SSHBanListener_SSH_BAN_LISTENER_MAIN

// fixture injects a deterministic clock without replacing the policy engine.
func fixture(t *testing.T, change func(*Config)) (*Guard, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	c := Config{Listener: mainListener, MaxFailures: 2, Duration: 5 * time.Minute, MaxEntries: 1000, Now: func() time.Time { return now }}
	if change != nil {
		change(&c)
	}
	g, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return g, &now
}

// TestPolicySnapshotsAreImmutableAndGenerationsIdentifyResets verifies API
// consumers can compare effective policies without confusing process restarts.
func TestPolicySnapshotsAreImmutableAndGenerationsIdentifyResets(t *testing.T) {
	a, _ := fixture(t, func(c *Config) { c.IgnoreCIDRs = []string{"192.0.2.0/24", "2001:db8::/32"} })
	b, _ := fixture(t, func(c *Config) { c.IgnoreCIDRs = []string{"2001:db8::/32", "192.0.2.0/24"} })
	first, second := snapshot(t, a, "198.51.100.1"), snapshot(t, b, "198.51.100.1")
	if first.Policy.Hash == "" || first.Policy.Hash != second.Policy.Hash || first.Generation == second.Generation {
		t.Fatal("policy and process identities conflated")
	}
	first.Policy.MaxFailures = 999
	if snapshot(t, a, "198.51.100.1").Policy.MaxFailures != 2 {
		t.Fatal("caller mutated effective enforcement policy")
	}
}

// snapshot reads the public control contract rather than the policy's map.
func snapshot(t *testing.T, g *Guard, ip string) *pb.GetSSHBanResponse {
	t.Helper()
	r, err := g.GetSSHBan(context.Background(), &pb.GetSSHBanRequest{Listener: mainListener, Ip: ip})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestSuccessfulBurstDoesNotConsumeFailureBudget distinguishes connection
// frequency from the failed-callback budget implicated in shared-NAT bans.
func TestSuccessfulBurstDoesNotConsumeFailureBudget(t *testing.T) {
	g, _ := fixture(t, nil)
	for i := range 200 {
		if err := g.Check(fmt.Sprintf("192.0.2.1:%d", 1000+i)); err != nil {
			t.Fatal(err)
		}
	}
	r := snapshot(t, g, "192.0.2.1")
	if r.Status.GetFailures() != 0 || r.Status.GetState() != pb.SSHBanState_SSH_BAN_STATE_TRACKING {
		t.Fatalf("successful bursts must only initialize the window: %v", r)
	}
}

// TestThresholdAndExpiryRemainAnchoredToFirstConnection pins upstream's fixed
// window, including recovery while blocked clients keep probing.
func TestThresholdAndExpiryRemainAnchoredToFirstConnection(t *testing.T) {
	g, now := fixture(t, nil)
	if err := g.Check("192.0.2.1:22"); err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(5 * time.Minute)
	*now = now.Add(4 * time.Minute)
	g.Fail("192.0.2.1:22", "auth_failure")
	g.Fail("192.0.2.1:22", "pipe_create_error")
	for range 20 {
		if err := g.Check("192.0.2.1:22"); err == nil {
			t.Fatal("threshold must block the source IP")
		}
		g.Fail("192.0.2.1:22", "pipe_create_error")
	}
	r := snapshot(t, g, "192.0.2.1")
	if !r.Status.GetExpiresAt().AsTime().Equal(deadline) {
		t.Fatalf("retries moved the fixed expiry: %v", r)
	}
	*now = deadline
	if err := g.Check("192.0.2.1:22"); err != nil {
		t.Fatalf("source must recover at expiry despite probing: %v", err)
	}
	if snapshot(t, g, "192.0.2.1").Status.GetFailures() != 0 {
		t.Fatal("new window retained failures")
	}
}

// TestExemptionsAndAddressNormalization ensures CIDRs cover both address
// families and mapped IPv4 cannot acquire an independent failure budget.
func TestExemptionsAndAddressNormalization(t *testing.T) {
	g, _ := fixture(t, func(c *Config) { c.IgnoreCIDRs = []string{"192.0.2.0/24", "2001:db8::/32"} })
	for _, addr := range []string{"192.0.2.3:22", "[::ffff:192.0.2.3]:22", "[2001:db8::3]:22"} {
		for range 10 {
			if err := g.Check(addr); err != nil {
				t.Fatal(err)
			}
			g.Fail(addr, "auth_failure")
		}
	}
	for _, ip := range []string{"192.0.2.3", "::ffff:192.0.2.3", "2001:db8::3"} {
		if snapshot(t, g, ip).Status.GetState() != pb.SSHBanState_SSH_BAN_STATE_EXEMPT {
			t.Fatalf("not exempt: %s", ip)
		}
	}
	g2, _ := fixture(t, nil)
	if err := g2.Check("[::ffff:198.51.100.1]:22"); err != nil {
		t.Fatal(err)
	}
	g2.Fail("198.51.100.1:22", "auth_failure")
	if snapshot(t, g2, "::ffff:198.51.100.1").Status.GetFailures() != 1 {
		t.Fatal("mapped address split the budget")
	}
}

// TestUnbanIsTargetedAndIdempotent proves an admin cannot accidentally clear
// unrelated sources when recovering one deployment's egress IP.
func TestUnbanIsTargetedAndIdempotent(t *testing.T) {
	g, _ := fixture(t, nil)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		if err := g.Check(ip + ":22"); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			g.Fail(ip+":22", "auth_failure")
		}
	}
	for i := range 2 {
		r, err := g.UnbanSSHSource(context.Background(), &pb.UnbanSSHSourceRequest{Listener: mainListener, Ip: "192.0.2.1", Reason: "regression test"})
		if err != nil || r.GetCleared() != (i == 0) {
			t.Fatalf("unban %d: %v %v", i, r, err)
		}
	}
	if snapshot(t, g, "192.0.2.2").Status.GetState() != pb.SSHBanState_SSH_BAN_STATE_BANNED {
		t.Fatal("unban cleared another IP")
	}
	if err := g.Check("192.0.2.1:22"); err != nil {
		t.Fatal(err)
	}
	if snapshot(t, g, "192.0.2.1").GetGeneration() == "" {
		t.Fatal("missing process generation")
	}
}

// TestConcurrentInitializationAndFailures detects lost increments and the
// concurrent first-connection initialization race in an IP's shared budget.
func TestConcurrentInitializationAndFailures(t *testing.T) {
	g, _ := fixture(t, func(c *Config) { c.MaxFailures = 1000 })
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			if err := g.Check("192.0.2.1:22"); err != nil {
				t.Error(err)
			}
			g.Fail("192.0.2.1:22", "auth_failure")
		})
	}
	wg.Wait()
	if n := snapshot(t, g, "192.0.2.1").Status.GetFailures(); n != 100 {
		t.Fatalf("lost concurrent increments: %d", n)
	}
}

// TestCapacityNeverEvictsAnActiveBan pins the explicit bounded-memory policy
// and verifies expiry makes room without weakening an existing ban.
func TestCapacityNeverEvictsAnActiveBan(t *testing.T) {
	g, now := fixture(t, func(c *Config) { c.MaxEntries = 1 })
	if err := g.Check("192.0.2.1:22"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		g.Fail("192.0.2.1:22", "auth_failure")
	}
	if err := g.Check("192.0.2.2:22"); err == nil {
		t.Fatal("capacity must reject a new untracked source")
	}
	if err := g.Check("192.0.2.1:22"); err == nil {
		t.Fatal("capacity evicted the active ban")
	}
	*now = now.Add(5 * time.Minute)
	if err := g.Check("192.0.2.2:22"); err != nil {
		t.Fatal("expired source did not free capacity", err)
	}
}

// TestInvalidConfigurationAndInputsFailClosed rejects malformed policy and
// target identities before they can mutate enforcement state.
func TestInvalidConfigurationAndInputsFailClosed(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.MaxFailures = 0 }, func(c *Config) { c.Duration = 0 }, func(c *Config) { c.MaxEntries = 0 },
		func(c *Config) { c.Listener = 0 }, func(c *Config) { c.IgnoreCIDRs = []string{"bad-prefix"} },
	} {
		c := Config{Listener: mainListener, MaxFailures: 2, Duration: time.Minute, MaxEntries: 10}
		change(&c)
		if _, err := New(c); err == nil {
			t.Errorf("accepted invalid config: %+v", c)
		}
	}
	g, _ := fixture(t, nil)
	if err := g.Check("bad-address"); err == nil {
		t.Error("accepted malformed source")
	}
	for _, r := range []*pb.GetSSHBanRequest{{Listener: mainListener, Ip: "192.0.2.0/24"}, {Listener: 0, Ip: "192.0.2.1"}, {Listener: pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS, Ip: "192.0.2.1"}} {
		if _, err := g.GetSSHBan(context.Background(), r); err == nil {
			t.Errorf("accepted invalid request: %v", r)
		}
	}
}

// TestEventsAreBoundedAndUnbanKeepsTheOperatorReason verifies operational
// evidence cannot turn retry traffic into an unbounded journal flood.
func TestEventsAreBoundedAndUnbanKeepsTheOperatorReason(t *testing.T) {
	var events []Event
	g, now := fixture(t, func(c *Config) { c.Emit = func(e Event) { events = append(events, e) } })
	if err := g.Check("192.0.2.1:22"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		g.Fail("192.0.2.1:22", "auth_failure")
	}
	for range 100 {
		_ = g.Check("192.0.2.1:22")
		g.Fail("192.0.2.1:22", "pipe_create_error")
	}
	if _, err := g.UnbanSSHSource(context.Background(), &pb.UnbanSSHSourceRequest{Listener: mainListener, Ip: "192.0.2.1", Reason: "repaired deploy key"}); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, e := range events {
		counts[e.Kind]++
		if e.Kind == "unban" && e.Reason != "repaired deploy key" {
			t.Fatal("operator reason was lost")
		}
	}
	if counts["ban"] != 1 || counts["blocked"] != 1 || len(events) > 6 {
		t.Fatalf("unexpected transition/log counts: %v", counts)
	}
	events = nil
	if err := g.Check("192.0.2.2:22"); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(5 * time.Minute)
	_ = snapshot(t, g, "192.0.2.2")
	if len(events) != 0 {
		t.Fatal("successful-source expiry should not spam ban events")
	}
}

// A window that ends with failures short of the budget reports them once
// (#2419); a quiet sentinel still reports them via Sweep, and a banned window
// is reported by its ban event, not also as a window summary.
func TestWindowFailuresAreReportedOnceAndBannedWindowsAreNot(t *testing.T) {
	var events []Event
	g, now := fixture(t, func(c *Config) { c.Emit = func(e Event) { events = append(events, e) } }) // MaxFailures 2
	kinds := func() []string {
		var k []string
		for _, e := range events {
			k = append(k, e.Kind)
		}
		return k
	}

	// 1.1.1.1: one failure, below the budget.
	_ = g.Check("203.0.113.1:1000")
	g.Fail("203.0.113.1:1000", "auth_failure")
	// 2.2.2.2: reaches the budget and is banned.
	_ = g.Check("203.0.113.2:1000")
	g.Fail("203.0.113.2:1000", "auth_failure")
	g.Fail("203.0.113.2:1000", "auth_failure")
	// 3.3.3.3: connects and never fails.
	_ = g.Check("203.0.113.3:1000")

	*now = now.Add(10 * time.Minute)
	g.Sweep() // no callback arrives; Sweep must still end the windows

	var window []Event
	for _, e := range events {
		if e.Kind == EventWindowFailures {
			window = append(window, e)
		}
	}
	if len(window) != 1 || window[0].IP != "203.0.113.1" || window[0].Failures != 1 {
		t.Fatalf("window_failures events = %+v (all: %v), want exactly one for 203.0.113.1 with 1 failure", window, kinds())
	}

	g.Sweep()
	n := 0
	for _, e := range events {
		if e.Kind == EventWindowFailures {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("a second Sweep re-reported the window: %d window_failures events", n)
	}
}

func TestTrySweepSkipsBusyGuardAndReportsOnNextPass(t *testing.T) {
	var summaries []Event
	g, now := fixture(t, func(c *Config) {
		c.Emit = func(e Event) {
			if e.Kind == EventWindowFailures {
				summaries = append(summaries, e)
			}
		}
	})
	if err := g.Check("203.0.113.1:22"); err != nil {
		t.Fatal(err)
	}
	g.Fail("203.0.113.1:22", "auth_failure")
	*now = now.Add(10 * time.Minute)
	g.mu.Lock()
	done := make(chan struct{})
	go func() { g.TrySweep(); close(done) }()
	select {
	case <-done: // a busy periodic pass must not wait for the policy mutex
	case <-time.After(2 * time.Second):
		g.mu.Unlock()
		<-done
		t.Fatal("busy periodic sweep blocked on the policy mutex")
	}
	g.mu.Unlock()
	if len(summaries) != 0 {
		t.Fatalf("busy sweep reported a window: %+v", summaries)
	}
	g.TrySweep()
	if len(summaries) != 1 || summaries[0].IP != "203.0.113.1" || summaries[0].Failures != 1 {
		t.Fatalf("next sweep summaries = %+v, want one failure", summaries)
	}
}
