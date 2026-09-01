package threatdetect

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeSink is a FindingSink test double: records every Upsert call without
// touching Postgres, so engine registry/fan-out/panic-isolation behavior is
// unit-testable independent of the store's own dedupe SQL (that lives in
// store_integration_test.go / mem_store_test.go).
type fakeSink struct {
	mu      sync.Mutex
	upserts []*Finding
	err     error
}

func (s *fakeSink) Upsert(_ context.Context, f *Finding) (*Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	s.upserts = append(s.upserts, f)
	return f, nil
}

func (s *fakeSink) calls() []*Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Finding(nil), s.upserts...)
}

// reset clears recorded upserts, for a multi-phase test that reuses one
// engine/sink across sequential scenarios.
func (s *fakeSink) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upserts = nil
}

// testRule is a Rule test double whose behavior is supplied per-test via
// closures, so each test stays a short table-driven case instead of a new
// named type.
type testRule struct {
	id      pb.ThreatRuleId
	onFlows func(RuleContext, []netbpf.FlowRecord) []RawFinding
	onDeny  func(RuleContext, netbpf.DenyEvent) []RawFinding
	onSweep func(RuleContext, time.Time) []RawFinding
}

func (r *testRule) ID() pb.ThreatRuleId { return r.id }

func (r *testRule) OnFlows(ctx RuleContext, flows []netbpf.FlowRecord) []RawFinding {
	if r.onFlows == nil {
		return nil
	}
	return r.onFlows(ctx, flows)
}

func (r *testRule) OnDeny(ctx RuleContext, ev netbpf.DenyEvent) []RawFinding {
	if r.onDeny == nil {
		return nil
	}
	return r.onDeny(ctx, ev)
}

func (r *testRule) Sweep(ctx RuleContext, now time.Time) []RawFinding {
	if r.onSweep == nil {
		return nil
	}
	return r.onSweep(ctx, now)
}

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestEngine_OnFlows_FansOutToEveryRegisteredRule(t *testing.T) {
	sink := &fakeSink{}
	e := NewEngine(sink, "backend-1", false, nil, fixedClock(time.Unix(0, 0)))

	ruleA := &testRule{id: pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION, onFlows: func(RuleContext, []netbpf.FlowRecord) []RawFinding {
		return []RawFinding{{Rule: pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION, Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH, TenantID: "t1", Subject: "203.0.113.9"}}
	}}
	ruleB := &testRule{id: pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW, onFlows: func(RuleContext, []netbpf.FlowRecord) []RawFinding {
		return []RawFinding{{Rule: pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW, Severity: pb.ThreatSeverity_THREAT_SEVERITY_CRITICAL, TenantID: "t1", Subject: "t2"}}
	}}
	e.Register(ruleA)
	e.Register(ruleB)

	e.OnFlows([]netbpf.FlowRecord{{Saddr: 1, Daddr: 2}})

	got := sink.calls()
	if len(got) != 2 {
		t.Fatalf("upserts = %d, want 2 (one per registered rule)", len(got))
	}
	byRule := map[pb.ThreatRuleId]*Finding{}
	for _, f := range got {
		byRule[f.Rule] = f
	}
	if f := byRule[pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION]; f == nil || f.BackendID != "backend-1" || f.Subject != "203.0.113.9" {
		t.Errorf("bad-destination finding = %+v, want backend-1/203.0.113.9", f)
	}
	if f := byRule[pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW]; f == nil || f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_CRITICAL {
		t.Errorf("cross-tenant finding = %+v, want CRITICAL", f)
	}
}

func TestEngine_OnDeny_FansOutToEveryRegisteredRule(t *testing.T) {
	sink := &fakeSink{}
	e := NewEngine(sink, "backend-1", false, nil, nil)

	rule := &testRule{id: pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST, onDeny: func(RuleContext, netbpf.DenyEvent) []RawFinding {
		return []RawFinding{{Rule: pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST, Severity: pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM, TenantID: "t1", Subject: ""}}
	}}
	e.Register(rule)

	e.OnDeny(netbpf.DenyEvent{TenantID: 1})

	got := sink.calls()
	if len(got) != 1 || got[0].Rule != pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST {
		t.Fatalf("upserts = %+v, want 1 deny-burst finding", got)
	}
}

func TestEngine_Sweep_DrivesTimeWindowRules(t *testing.T) {
	sink := &fakeSink{}
	e := NewEngine(sink, "backend-1", false, nil, nil)

	var sawNow time.Time
	rule := &testRule{id: pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST, onSweep: func(_ RuleContext, now time.Time) []RawFinding {
		sawNow = now
		return []RawFinding{{Rule: pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST, TenantID: "t1"}}
	}}
	e.Register(rule)

	tick := time.Unix(1000, 0)
	e.Sweep(tick)

	if len(sink.calls()) != 1 {
		t.Fatalf("upserts = %d, want 1", len(sink.calls()))
	}
	if !sawNow.Equal(tick) {
		t.Errorf("rule saw now = %v, want %v", sawNow, tick)
	}
}

// A rule that returns no findings for a signal must never reach the sink —
// otherwise every quiet poll would upsert an empty/zero-value finding.
func TestEngine_NoFindings_NeverUpserts(t *testing.T) {
	sink := &fakeSink{}
	e := NewEngine(sink, "backend-1", false, nil, nil)
	e.Register(&testRule{id: pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION})

	e.OnFlows([]netbpf.FlowRecord{{Saddr: 1}})
	e.OnDeny(netbpf.DenyEvent{})
	e.Sweep(time.Now())

	if got := sink.calls(); len(got) != 0 {
		t.Fatalf("upserts = %+v, want none", got)
	}
}

// Repeated firing calls Upsert every time — the engine does not dedupe
// itself. Dedupe (repeat ⇒ count++, no duplicate row) is the sink's job via
// the security_findings_open_dedupe unique index; see
// store_integration_test.go (FindingStore) and mem_store_test.go
// (MemFindingStore) for that behavior proven end to end.
func TestEngine_RepeatedFinding_CallsUpsertEveryTime(t *testing.T) {
	sink := &fakeSink{}
	e := NewEngine(sink, "backend-1", false, nil, nil)
	rule := &testRule{id: pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION, onFlows: func(RuleContext, []netbpf.FlowRecord) []RawFinding {
		return []RawFinding{{Rule: pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION, TenantID: "t1", Subject: "203.0.113.9"}}
	}}
	e.Register(rule)

	for i := 0; i < 3; i++ {
		e.OnFlows([]netbpf.FlowRecord{{Saddr: 1}})
	}

	if got := sink.calls(); len(got) != 3 {
		t.Fatalf("upserts = %d, want 3 (dedupe is the sink's responsibility, not the engine's)", len(got))
	}
}

// A panicking rule is recovered, marked unhealthy, and never takes down the
// engine or blocks other rules from running.
func TestEngine_RulePanic_IsolatedFromOtherRules(t *testing.T) {
	sink := &fakeSink{}
	e := NewEngine(sink, "backend-1", false, nil, fixedClock(time.Unix(42, 0)))

	panicky := &testRule{id: pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION, onFlows: func(RuleContext, []netbpf.FlowRecord) []RawFinding {
		panic("boom")
	}}
	healthy := &testRule{id: pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW, onFlows: func(RuleContext, []netbpf.FlowRecord) []RawFinding {
		return []RawFinding{{Rule: pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW, TenantID: "t1"}}
	}}
	e.Register(panicky)
	e.Register(healthy)

	e.OnFlows([]netbpf.FlowRecord{{Saddr: 1}}) // must not panic the test

	got := sink.calls()
	if len(got) != 1 || got[0].Rule != pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW {
		t.Fatalf("upserts = %+v, want exactly the healthy rule's finding", got)
	}

	_, rules := e.Status()
	byRule := map[pb.ThreatRuleId]RuleStatusInfo{}
	for _, r := range rules {
		byRule[r.Rule] = r
	}
	bad := byRule[pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION]
	if bad.Healthy {
		t.Errorf("panicking rule reported healthy: %+v", bad)
	}
	if bad.LastError == "" || bad.LastErrorAt.Unix() != 42 {
		t.Errorf("panicking rule status = %+v, want a non-empty error at t=42", bad)
	}
	good := byRule[pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW]
	if !good.Healthy {
		t.Errorf("healthy rule reported unhealthy: %+v", good)
	}

	// The engine keeps running after the panic: a second call still reaches
	// the healthy rule.
	e.OnFlows([]netbpf.FlowRecord{{Saddr: 1}})
	if len(sink.calls()) != 2 {
		t.Fatalf("upserts after second call = %d, want 2 (engine survives a rule panic)", len(sink.calls()))
	}
}

func TestEngine_Status_ReportsDegradedFlag(t *testing.T) {
	e := NewEngine(&fakeSink{}, "backend-1", true, nil, nil)
	degraded, rules := e.Status()
	if !degraded {
		t.Error("degraded = false, want true")
	}
	if len(rules) != 0 {
		t.Errorf("rules = %+v, want none registered", rules)
	}
}

func TestEngine_RuleContext_TenantForIP(t *testing.T) {
	sink := &fakeSink{}
	lookup := func(ip netip.Addr) (string, bool) {
		if ip == netip.MustParseAddr("10.0.0.5") {
			return "tenant-a", true
		}
		return "", false
	}
	e := NewEngine(sink, "backend-1", false, lookup, nil)

	var gotTenant string
	var gotOK bool
	rule := &testRule{id: pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW, onFlows: func(ctx RuleContext, _ []netbpf.FlowRecord) []RawFinding {
		gotTenant, gotOK = ctx.TenantForIP(netip.MustParseAddr("10.0.0.5"))
		return nil
	}}
	e.Register(rule)
	e.OnFlows([]netbpf.FlowRecord{{Saddr: 1}})

	if !gotOK || gotTenant != "tenant-a" {
		t.Errorf("TenantForIP = (%q, %v), want (tenant-a, true)", gotTenant, gotOK)
	}
}
