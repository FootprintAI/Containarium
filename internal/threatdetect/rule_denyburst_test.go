package threatdetect

import (
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func denyburstCtx(now time.Time, tenants map[string]string) RuleContext {
	return RuleContext{
		TenantForIP: fakeTenants(tenants),
		Now:         func() time.Time { return now },
	}
}

func TestDenyBurstRule_ID(t *testing.T) {
	r := NewDenyBurstRule(0, 0)
	if r.ID() != pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST {
		t.Errorf("ID() = %v, want THREAT_RULE_ID_DENY_BURST", r.ID())
	}
}

func TestNewDenyBurstRule_DefaultsOnZeroValue(t *testing.T) {
	r := NewDenyBurstRule(0, 0)
	if r.n != DefaultDenyBurstN {
		t.Errorf("n = %d, want default %d", r.n, DefaultDenyBurstN)
	}
	if r.window != DefaultDenyBurstWindow {
		t.Errorf("window = %v, want default %v", r.window, DefaultDenyBurstWindow)
	}
}

// OnDeny alone never fires — evaluation is deferred to Sweep (see the type
// doc). This must hold even once the threshold is technically met.
func TestDenyBurstRule_OnDeny_NeverFiresDirectly(t *testing.T) {
	r := NewDenyBurstRule(1, time.Minute)
	tenants := map[string]string{"10.0.0.1": "alice"}
	base := time.Unix(1000, 0)

	for i := 0; i < 5; i++ {
		ev := netbpf.DenyEvent{Saddr: beIP(10, 0, 0, 1), Daddr: beIP(10, 0, 0, 2)}
		if got := r.OnDeny(denyburstCtx(base, tenants), ev); got != nil {
			t.Fatalf("OnDeny returned %+v, want nil (Sweep-driven, not signal-driven)", got)
		}
	}
}

// Unresolved source IP: dropped, never attributed to a guessed tenant.
func TestDenyBurstRule_OnDeny_UnknownSourceDropped(t *testing.T) {
	r := NewDenyBurstRule(1, time.Minute)
	base := time.Unix(1000, 0)
	ev := netbpf.DenyEvent{Saddr: beIP(192, 168, 1, 1), Daddr: beIP(10, 0, 0, 2)}
	r.OnDeny(denyburstCtx(base, nil), ev)

	got := r.Sweep(denyburstCtx(base, nil), base)
	if len(got) != 0 {
		t.Fatalf("Sweep = %+v, want none (unresolved source never recorded)", got)
	}
}

// The design doc's own table: N-1 denies -> none, N -> MEDIUM.
func TestDenyBurstRule_NMinusOneVsN(t *testing.T) {
	const n = 5
	tenants := map[string]string{"10.0.0.1": "alice"}
	base := time.Unix(1000, 0)
	r := NewDenyBurstRule(n, time.Minute)

	fireEvents := func(count int) []RawFinding {
		for i := 0; i < count; i++ {
			ev := netbpf.DenyEvent{Saddr: beIP(10, 0, 0, 1), Daddr: beIP(10, 0, 0, 2), Dport: 1234, Proto: 6}
			r.OnDeny(denyburstCtx(base, tenants), ev)
		}
		return r.Sweep(denyburstCtx(base, tenants), base)
	}

	if got := fireEvents(n - 1); len(got) != 0 {
		t.Fatalf("after %d denies, Sweep = %+v, want none", n-1, got)
	}
	// One more deny crosses the threshold (total n).
	ev := netbpf.DenyEvent{Saddr: beIP(10, 0, 0, 1), Daddr: beIP(10, 0, 0, 2), Dport: 1234, Proto: 6}
	r.OnDeny(denyburstCtx(base, tenants), ev)
	got := r.Sweep(denyburstCtx(base, tenants), base)
	if len(got) != 1 {
		t.Fatalf("after %d denies, Sweep = %+v, want exactly 1 MEDIUM finding", n, got)
	}
	f := got[0]
	if f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM {
		t.Errorf("Severity = %v, want MEDIUM", f.Severity)
	}
	if f.TenantID != "alice" {
		t.Errorf("TenantID = %q, want alice", f.TenantID)
	}
	if f.Subject != "" {
		t.Errorf("Subject = %q, want empty (tenant-scoped, not destination-scoped)", f.Subject)
	}
}

// Once fired, a Sweep with no new denies since must not keep re-firing —
// the store already collapses repeats, but the rule itself shouldn't
// manufacture a "repeat" out of nothing happening.
func TestDenyBurstRule_NoNewDenies_DoesNotRefire(t *testing.T) {
	const n = 3
	tenants := map[string]string{"10.0.0.1": "alice"}
	base := time.Unix(1000, 0)
	r := NewDenyBurstRule(n, time.Minute)

	for i := 0; i < n; i++ {
		ev := netbpf.DenyEvent{Saddr: beIP(10, 0, 0, 1)}
		r.OnDeny(denyburstCtx(base, tenants), ev)
	}
	first := r.Sweep(denyburstCtx(base, tenants), base)
	if len(first) != 1 {
		t.Fatalf("first Sweep = %+v, want 1 finding", first)
	}

	// No new OnDeny; Sweep again a few seconds later (still inside window).
	second := r.Sweep(denyburstCtx(base, tenants), base.Add(5*time.Second))
	if len(second) != 0 {
		t.Fatalf("second Sweep (no new denies) = %+v, want none", second)
	}
}

// Window expiry: once every record ages out, the count resets below n and
// a fresh burst is required to fire again.
func TestDenyBurstRule_WindowExpiryResets(t *testing.T) {
	const n = 3
	window := time.Minute
	tenants := map[string]string{"10.0.0.1": "alice"}
	base := time.Unix(1000, 0)
	r := NewDenyBurstRule(n, window)

	for i := 0; i < n; i++ {
		r.OnDeny(denyburstCtx(base, tenants), netbpf.DenyEvent{Saddr: beIP(10, 0, 0, 1)})
	}
	if got := r.Sweep(denyburstCtx(base, tenants), base); len(got) != 1 {
		t.Fatalf("initial burst Sweep = %+v, want 1 finding", got)
	}

	// Jump past the window with no new denies: old records should be
	// pruned and the tenant's tracked state cleared.
	afterExpiry := base.Add(window + time.Second)
	if got := r.Sweep(denyburstCtx(afterExpiry, tenants), afterExpiry); len(got) != 0 {
		t.Fatalf("Sweep after window expiry = %+v, want none", got)
	}

	// Fewer than n new denies after expiry: still no finding.
	for i := 0; i < n-1; i++ {
		r.OnDeny(denyburstCtx(afterExpiry, tenants), netbpf.DenyEvent{Saddr: beIP(10, 0, 0, 1)})
	}
	if got := r.Sweep(denyburstCtx(afterExpiry, tenants), afterExpiry); len(got) != 0 {
		t.Fatalf("Sweep with %d fresh denies post-expiry = %+v, want none (need a fresh full burst)", n-1, got)
	}

	// One more closes the fresh burst back to n.
	r.OnDeny(denyburstCtx(afterExpiry, tenants), netbpf.DenyEvent{Saddr: beIP(10, 0, 0, 1)})
	if got := r.Sweep(denyburstCtx(afterExpiry, tenants), afterExpiry); len(got) != 1 {
		t.Fatalf("Sweep after fresh burst re-crosses n = %+v, want 1 finding", got)
	}
}

// N and M are both operator-tunable constructor parameters.
func TestDenyBurstRule_TunableNAndM(t *testing.T) {
	tenants := map[string]string{"10.0.0.1": "alice"}
	base := time.Unix(1000, 0)

	// A tight rule (n=1) fires on the very first deny.
	tight := NewDenyBurstRule(1, time.Hour)
	tight.OnDeny(denyburstCtx(base, tenants), netbpf.DenyEvent{Saddr: beIP(10, 0, 0, 1)})
	if got := tight.Sweep(denyburstCtx(base, tenants), base); len(got) != 1 {
		t.Fatalf("n=1 rule Sweep after 1 deny = %+v, want 1 finding", got)
	}

	// A short window (M) expires almost immediately.
	short := NewDenyBurstRule(2, time.Second)
	short.OnDeny(denyburstCtx(base, tenants), netbpf.DenyEvent{Saddr: beIP(10, 0, 0, 1)})
	short.OnDeny(denyburstCtx(base, tenants), netbpf.DenyEvent{Saddr: beIP(10, 0, 0, 1)})
	later := base.Add(2 * time.Second)
	if got := short.Sweep(denyburstCtx(later, tenants), later); len(got) != 0 {
		t.Fatalf("short-window rule Sweep after window elapsed = %+v, want none", got)
	}
}

// Different tenants accumulate independent windows.
func TestDenyBurstRule_DistinctTenantsDoNotCollide(t *testing.T) {
	const n = 2
	tenants := map[string]string{"10.0.0.1": "alice", "10.0.0.9": "bob"}
	base := time.Unix(1000, 0)
	r := NewDenyBurstRule(n, time.Minute)

	r.OnDeny(denyburstCtx(base, tenants), netbpf.DenyEvent{Saddr: beIP(10, 0, 0, 1)})
	r.OnDeny(denyburstCtx(base, tenants), netbpf.DenyEvent{Saddr: beIP(10, 0, 0, 1)})
	// Bob only has 1 deny — below n.
	r.OnDeny(denyburstCtx(base, tenants), netbpf.DenyEvent{Saddr: beIP(10, 0, 0, 9)})

	got := r.Sweep(denyburstCtx(base, tenants), base)
	if len(got) != 1 {
		t.Fatalf("Sweep = %+v, want exactly 1 finding (alice only)", got)
	}
	if got[0].TenantID != "alice" {
		t.Errorf("TenantID = %q, want alice", got[0].TenantID)
	}
}

func TestDenyBurstRule_OnFlows_IsNoop(t *testing.T) {
	r := NewDenyBurstRule(1, time.Minute)
	if got := r.OnFlows(RuleContext{}, []netbpf.FlowRecord{{}}); got != nil {
		t.Errorf("OnFlows = %+v, want nil (deny-shaped rule)", got)
	}
}

func TestDenyEvidenceFromRecords_AggregatesByDestination(t *testing.T) {
	base := time.Unix(1000, 0)
	records := []denyBurstRecord{
		{at: base, dst: "10.0.0.2", dport: 22, proto: "tcp", reason: "policy"},
		{at: base, dst: "10.0.0.2", dport: 22, proto: "tcp", reason: "policy"},
		{at: base, dst: "10.0.0.3", dport: 443, proto: "tcp", reason: "policy"},
	}
	got := denyEvidenceFromRecords(records)
	if len(got) != 2 {
		t.Fatalf("evidence = %+v, want 2 groups", got)
	}
	if got[0].DstIP != "10.0.0.2" || got[0].Count != 2 {
		t.Errorf("first group = %+v, want 10.0.0.2 count=2", got[0])
	}
	if got[1].DstIP != "10.0.0.3" || got[1].Count != 1 {
		t.Errorf("second group = %+v, want 10.0.0.3 count=1", got[1])
	}
}
