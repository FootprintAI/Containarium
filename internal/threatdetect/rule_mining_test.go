package threatdetect

import (
	"net/netip"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeDestMatcher is a DestinationMatcher test double over exact IPs.
type fakeDestMatcher map[string]string

func (m fakeDestMatcher) MatchDestination(ip netip.Addr) (string, bool) {
	cidr, ok := m[ip.String()]
	return cidr, ok
}

const miningBoxIP = "10.0.0.5"

// miningScenario drives a MiningBehaviorRule on a fake clock: CPU samples
// every 15s from t0 for `span`, and one flow observed on every flow poll in
// the final `flowSeen` of that span whose own age (LastNs-FirstNs) is
// flowAge. Returns the findings of a single Sweep at the end of the span.
type miningScenario struct {
	cores      float64
	limitCores float64
	span       time.Duration
	dst        [4]byte
	dport      uint16
	flowAge    time.Duration
	flowSeen   time.Duration
	matcher    DestinationMatcher
	thresholds func() MiningThresholds
}

var miningT0 = time.Unix(1_760_140_800, 0) // 2025-10-11T00:00:00Z

func (s miningScenario) run(t *testing.T, r *MiningBehaviorRule) (time.Time, []RawFinding) {
	t.Helper()
	tenants := map[string]string{miningBoxIP: "alice"}
	now := miningT0
	ctx := func() RuleContext {
		return RuleContext{
			TenantForIP:      fakeTenants(tenants),
			Now:              func() time.Time { return now },
			MiningThresholds: s.thresholds,
		}
	}
	ip := netip.MustParseAddr(miningBoxIP)
	end := miningT0.Add(s.span)
	for now = miningT0; !now.After(end); now = now.Add(15 * time.Second) {
		r.OnCPU(ctx(), []CPUSample{{Container: "box", IP: ip, Cores: s.cores, LimitCores: s.limitCores, At: now}})
		if s.flowSeen > 0 && !now.Before(end.Add(-s.flowSeen)) {
			fr := netbpf.FlowRecord{
				Saddr: beIP(10, 0, 0, 5), Daddr: beIP(s.dst[0], s.dst[1], s.dst[2], s.dst[3]),
				Sport: 40000, Dport: s.dport, Proto: 6, Bytes: 4096, Packets: 32,
				FirstNs: 1_000, LastNs: 1_000 + uint64(s.flowAge.Nanoseconds()), // #nosec G115 -- test durations are positive
			}
			r.OnFlows(ctx(), []netbpf.FlowRecord{fr})
		}
	}
	now = end
	return end, r.Sweep(ctx(), end)
}

func TestMiningBehaviorRule_Table(t *testing.T) {
	pool := [4]byte{203, 0, 113, 9}
	web := [4]byte{198, 51, 100, 7}
	cases := []struct {
		name string
		s    miningScenario
		want int
	}{
		// AC3: the 2026-10-11 shape — 16 busy cores, 20-minute flow to :3333.
		{"incident replay 16 cores + 20m stratum flow", miningScenario{cores: 16, limitCores: 16, span: 20 * time.Minute, dst: pool, dport: 3333, flowAge: 20 * time.Minute, flowSeen: 20 * time.Minute}, 1},
		{"5m at 2.0 cores + 4m flow to :3333", miningScenario{cores: 2.0, span: 5 * time.Minute, dst: pool, dport: 3333, flowAge: 4 * time.Minute, flowSeen: 4 * time.Minute}, 1},
		// AC3: a build job at 100% CPU with only :443 flows.
		{"build job 100% CPU, only :443", miningScenario{cores: 16, limitCores: 16, span: 20 * time.Minute, dst: web, dport: 443, flowAge: 20 * time.Minute, flowSeen: 20 * time.Minute}, 0},
		// AC1/AC3: the bar is min(min_cores, 0.75 x limits.cpu).
		{"1-vCPU box at 0.8 cores + :3333", miningScenario{cores: 0.8, limitCores: 1, span: 6 * time.Minute, dst: pool, dport: 3333, flowAge: 4 * time.Minute, flowSeen: 4 * time.Minute}, 1},
		{"1-vCPU box at 0.6 cores + :3333", miningScenario{cores: 0.6, limitCores: 1, span: 6 * time.Minute, dst: pool, dport: 3333, flowAge: 4 * time.Minute, flowSeen: 4 * time.Minute}, 0},
		{"no limit uses min_cores alone: 1.2 cores", miningScenario{cores: 1.2, limitCores: 0, span: 6 * time.Minute, dst: pool, dport: 3333, flowAge: 4 * time.Minute, flowSeen: 4 * time.Minute}, 0},
		{"8-vCPU box trips at 1.5 not 6", miningScenario{cores: 1.6, limitCores: 8, span: 6 * time.Minute, dst: pool, dport: 3333, flowAge: 4 * time.Minute, flowSeen: 4 * time.Minute}, 1},
		{"low CPU 0.4 cores + :3333", miningScenario{cores: 0.4, span: 6 * time.Minute, dst: pool, dport: 3333, flowAge: 4 * time.Minute, flowSeen: 4 * time.Minute}, 0},
		{"flow younger than flow_min_age", miningScenario{cores: 4, span: 6 * time.Minute, dst: pool, dport: 3333, flowAge: 2 * time.Minute, flowSeen: 2 * time.Minute}, 0},
		{"CPU history shorter than window", miningScenario{cores: 4, span: 3 * time.Minute, dst: pool, dport: 3333, flowAge: 4 * time.Minute, flowSeen: 3 * time.Minute}, 0},
		{"bad-destination hit on :443 qualifies", miningScenario{cores: 4, span: 6 * time.Minute, dst: web, dport: 443, flowAge: 4 * time.Minute, flowSeen: 4 * time.Minute, matcher: fakeDestMatcher{"198.51.100.7": "198.51.100.0/24"}}, 1},
		// AC2: thresholds from RuleContext are honoured.
		{"operator raises min_cores to 8", miningScenario{cores: 4, span: 6 * time.Minute, dst: pool, dport: 3333, flowAge: 4 * time.Minute, flowSeen: 4 * time.Minute, thresholds: func() MiningThresholds {
			th := DefaultMiningThresholds()
			th.MinCores = 8
			return th
		}}, 0},
		{"operator adds port 9999", miningScenario{cores: 4, span: 6 * time.Minute, dst: pool, dport: 9999, flowAge: 4 * time.Minute, flowSeen: 4 * time.Minute, thresholds: func() MiningThresholds {
			th := DefaultMiningThresholds()
			th.StratumPorts = []uint32{9999}
			return th
		}}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := tc.s.run(t, NewMiningBehaviorRule(tc.s.matcher))
			if len(got) != tc.want {
				t.Fatalf("Sweep returned %d findings, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

func TestMiningBehaviorRule_FindingShape(t *testing.T) {
	s := miningScenario{cores: 16, limitCores: 16, span: 20 * time.Minute, dst: [4]byte{203, 0, 113, 9}, dport: 3333, flowAge: 20 * time.Minute, flowSeen: 20 * time.Minute}
	_, got := s.run(t, NewMiningBehaviorRule(nil))
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if f.Rule != pb.ThreatRuleId_THREAT_RULE_ID_MINING_BEHAVIOR || f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_HIGH {
		t.Errorf("rule/severity = %v/%v, want MINING_BEHAVIOR/HIGH", f.Rule, f.Severity)
	}
	if f.Subject != "203.0.113.9:3333" || f.TenantID != "alice" || f.Container != "box" {
		t.Errorf("subject/tenant/container = %q/%q/%q", f.Subject, f.TenantID, f.Container)
	}
	if len(f.Evidence.CPU) != 1 {
		t.Fatalf("CPU evidence = %+v, want exactly one", f.Evidence.CPU)
	}
	cpu := f.Evidence.CPU[0]
	if cpu.MeanCores != 16 || cpu.PeakCores != 16 || cpu.WindowSeconds != 300 || cpu.Samples != 20 {
		t.Errorf("CPU evidence = %+v, want mean 16 peak 16 window 300s 20 samples", cpu)
	}
	if len(f.Evidence.Flows) != 1 {
		t.Fatalf("flow evidence = %+v, want one", f.Evidence.Flows)
	}
	fl := f.Evidence.Flows[0]
	if fl.SrcIP != miningBoxIP || fl.DstIP != "203.0.113.9" || fl.DstPort != 3333 || fl.Protocol != "tcp" || fl.Bytes != 4096 {
		t.Errorf("flow evidence = %+v", fl)
	}
}

// A second pool opens a second finding (distinct subject); the same pool on
// the next sweep re-fires the same subject, which the store dedupes.
func TestMiningBehaviorRule_SubjectPerDestination(t *testing.T) {
	r := NewMiningBehaviorRule(nil)
	s := miningScenario{cores: 4, span: 6 * time.Minute, dst: [4]byte{203, 0, 113, 9}, dport: 3333, flowAge: 4 * time.Minute, flowSeen: 4 * time.Minute}
	end, first := s.run(t, r)
	if len(first) != 1 {
		t.Fatalf("first sweep: %d findings, want 1", len(first))
	}
	ctx := RuleContext{TenantForIP: fakeTenants(map[string]string{miningBoxIP: "alice"}), Now: fixedClock(end)}
	second := netbpf.FlowRecord{Saddr: beIP(10, 0, 0, 5), Daddr: beIP(192, 0, 2, 44), Sport: 40001, Dport: 4444, Proto: 6, FirstNs: 1, LastNs: 1 + uint64((5 * time.Minute).Nanoseconds())} // #nosec G115 -- positive constant
	r.OnFlows(ctx, []netbpf.FlowRecord{second})
	got := r.Sweep(ctx, end.Add(30*time.Second))
	subjects := map[string]bool{}
	for _, f := range got {
		subjects[f.Subject] = true
	}
	if len(got) != 2 || !subjects["203.0.113.9:3333"] || !subjects["192.0.2.44:4444"] {
		t.Fatalf("second sweep subjects = %v, want both pools", subjects)
	}
}

// Per-container state expires when no sample arrives for 2 x window, and a
// candidate flow not seen inside the window stops qualifying.
func TestMiningBehaviorRule_StateExpires(t *testing.T) {
	r := NewMiningBehaviorRule(nil)
	s := miningScenario{cores: 4, span: 6 * time.Minute, dst: [4]byte{203, 0, 113, 9}, dport: 3333, flowAge: 4 * time.Minute, flowSeen: 4 * time.Minute}
	end, got := s.run(t, r)
	if len(got) != 1 {
		t.Fatalf("precondition: %d findings, want 1", len(got))
	}
	ctx := RuleContext{TenantForIP: fakeTenants(nil), Now: fixedClock(end)}
	if got := r.Sweep(ctx, end.Add(10*time.Minute+time.Second)); len(got) != 0 {
		t.Fatalf("after 2 x window with no samples: %d findings, want 0", len(got))
	}
	if n := r.trackedContainers(); n != 0 {
		t.Fatalf("tracked containers after expiry = %d, want 0", n)
	}
}

func TestMiningBehaviorRule_OnDenyNoop_ID(t *testing.T) {
	r := NewMiningBehaviorRule(nil)
	if r.ID() != pb.ThreatRuleId_THREAT_RULE_ID_MINING_BEHAVIOR {
		t.Errorf("ID() = %v", r.ID())
	}
	if got := r.OnDeny(RuleContext{}, netbpf.DenyEvent{}); got != nil {
		t.Errorf("OnDeny = %+v, want nil", got)
	}
	var _ CPUConsumer = r
}

// AC3 end to end through the engine: the 2026-10-11 shape yields exactly one
// HIGH upsert on one sweep, and the next sweep re-upserts the same dedupe key
// (rule, tenant, subject), which the finding store folds into one open row.
func TestMiningBehaviorRule_EngineReplay_OneFindingPerSweepSameDedupeKey(t *testing.T) {
	now := miningT0
	sink := &fakeSink{}
	e := NewEngine(sink, "b1", false, fakeTenants(map[string]string{miningBoxIP: "alice"}), func() time.Time { return now })
	e.Register(NewMiningBehaviorRule(nil))
	ip := netip.MustParseAddr(miningBoxIP)
	flow := netbpf.FlowRecord{Saddr: beIP(10, 0, 0, 5), Daddr: beIP(203, 0, 113, 9), Sport: 40000, Dport: 3333, Proto: 6, FirstNs: 1}
	for ; !now.After(miningT0.Add(20 * time.Minute)); now = now.Add(15 * time.Second) {
		e.OnCPU([]CPUSample{{Container: "box", IP: ip, Cores: 16, LimitCores: 16, At: now}})
		flow.LastNs = 1 + uint64(now.Sub(miningT0).Nanoseconds()) // #nosec G115 -- positive test duration
		e.OnFlows([]netbpf.FlowRecord{flow})
	}
	if len(sink.calls()) != 0 {
		t.Fatalf("findings before any sweep: %d, want 0 (Sweep-driven)", len(sink.calls()))
	}
	e.Sweep(now)
	e.Sweep(now.Add(30 * time.Second))
	calls := sink.calls()
	if len(calls) != 2 {
		t.Fatalf("upserts over two sweeps = %d, want 2 (one per sweep)", len(calls))
	}
	for _, f := range calls {
		if f.Rule != pb.ThreatRuleId_THREAT_RULE_ID_MINING_BEHAVIOR || f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_HIGH || f.TenantID != "alice" || f.Subject != "203.0.113.9:3333" {
			t.Fatalf("upsert = %+v, want HIGH mining-behavior alice/203.0.113.9:3333", f)
		}
	}
}

// AC "evidence: ... first/last seen, and the matched port or list entry":
// the qualifying flow carries wall-clock first/last seen (last = the flow
// poll that reported it, first = last minus the flow's own age, the same
// anchoring flowsToEBPF uses for the traffic view) and what qualified it.
func TestMiningBehaviorRule_FlowEvidenceSeenAndMatched(t *testing.T) {
	pool := [4]byte{203, 0, 113, 9}
	web := [4]byte{198, 51, 100, 7}
	cases := []struct {
		name        string
		s           miningScenario
		wantMatched string
	}{
		{"stratum port", miningScenario{cores: 4, span: 6 * time.Minute, dst: pool, dport: 3333, flowAge: 4 * time.Minute, flowSeen: 4 * time.Minute}, "port:3333"},
		{"listed destination on :443", miningScenario{cores: 4, span: 6 * time.Minute, dst: web, dport: 443, flowAge: 4 * time.Minute, flowSeen: 4 * time.Minute, matcher: fakeDestMatcher{"198.51.100.7": "198.51.100.0/24"}}, "bad-destination:198.51.100.0/24"},
		{"listed destination on a stratum port names the list entry", miningScenario{cores: 4, span: 6 * time.Minute, dst: web, dport: 4444, flowAge: 4 * time.Minute, flowSeen: 4 * time.Minute, matcher: fakeDestMatcher{"198.51.100.7": "198.51.100.7/32"}}, "bad-destination:198.51.100.7/32"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			end, got := tc.s.run(t, NewMiningBehaviorRule(tc.s.matcher))
			if len(got) != 1 || len(got[0].Evidence.Flows) != 1 {
				t.Fatalf("got %+v, want one finding with one flow", got)
			}
			fl := got[0].Evidence.Flows[0]
			if fl.Matched != tc.wantMatched {
				t.Errorf("Matched = %q, want %q", fl.Matched, tc.wantMatched)
			}
			if !fl.LastSeen.Equal(end) {
				t.Errorf("LastSeen = %v, want the last flow poll %v", fl.LastSeen, end)
			}
			if want := end.Add(-tc.s.flowAge); !fl.FirstSeen.Equal(want) {
				t.Errorf("FirstSeen = %v, want %v (last seen minus flow age)", fl.FirstSeen, want)
			}
		})
	}
}
