package threatdetect

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// beIP encodes a dotted-quad as the network-byte-order uint32 FlowRecord and
// DenyEvent carry on the wire (mirrors internal/netbpf's own test helpers).
func beIP(a, b, c, d byte) uint32 {
	return binary.NativeEndian.Uint32([]byte{a, b, c, d})
}

// fakeTenants is a RuleContext.TenantForIP double: a fixed IP->tenant map,
// everything else unresolved. Both new rules must never guess at an
// unrecognized IP, so "not in the map" is the interesting case to exercise,
// not an edge case to skip.
func fakeTenants(m map[string]string) func(netip.Addr) (string, bool) {
	return func(ip netip.Addr) (string, bool) {
		t, ok := m[ip.String()]
		return t, ok
	}
}

func TestCrossTenantFlowRule_ID(t *testing.T) {
	r := NewCrossTenantFlowRule()
	if r.ID() != pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW {
		t.Errorf("ID() = %v, want THREAT_RULE_ID_CROSS_TENANT_FLOW", r.ID())
	}
}

func TestCrossTenantFlowRule_OnFlows(t *testing.T) {
	tenants := fakeTenants(map[string]string{
		"10.0.0.1": "alice",
		"10.0.0.2": "alice",
		"10.0.0.3": "bob",
	})
	ctx := RuleContext{TenantForIP: tenants}

	tests := []struct {
		name     string
		flow     netbpf.FlowRecord
		wantFire bool
		wantSev  pb.ThreatSeverity
		wantTID  string
		wantSubj string
	}{
		{
			name:     "same tenant both ends: no finding",
			flow:     netbpf.FlowRecord{Saddr: beIP(10, 0, 0, 1), Daddr: beIP(10, 0, 0, 2)},
			wantFire: false,
		},
		{
			name:     "different tenants: CRITICAL finding attributed to src, subject is peer tenant",
			flow:     netbpf.FlowRecord{Saddr: beIP(10, 0, 0, 1), Daddr: beIP(10, 0, 0, 3)},
			wantFire: true,
			wantSev:  pb.ThreatSeverity_THREAT_SEVERITY_CRITICAL,
			wantTID:  "alice",
			wantSubj: "bob",
		},
		{
			name:     "unknown source: no finding, never guess",
			flow:     netbpf.FlowRecord{Saddr: beIP(192, 168, 1, 1), Daddr: beIP(10, 0, 0, 3)},
			wantFire: false,
		},
		{
			name:     "unknown destination: no finding, never guess",
			flow:     netbpf.FlowRecord{Saddr: beIP(10, 0, 0, 1), Daddr: beIP(192, 168, 1, 1)},
			wantFire: false,
		},
		{
			name:     "both unknown: no finding",
			flow:     netbpf.FlowRecord{Saddr: beIP(192, 168, 1, 1), Daddr: beIP(192, 168, 1, 2)},
			wantFire: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewCrossTenantFlowRule()
			got := r.OnFlows(ctx, []netbpf.FlowRecord{tc.flow})
			if !tc.wantFire {
				if len(got) != 0 {
					t.Fatalf("OnFlows = %+v, want no finding", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("OnFlows = %+v, want exactly 1 finding", got)
			}
			f := got[0]
			if f.Severity != tc.wantSev {
				t.Errorf("Severity = %v, want %v", f.Severity, tc.wantSev)
			}
			if f.TenantID != tc.wantTID {
				t.Errorf("TenantID = %q, want %q", f.TenantID, tc.wantTID)
			}
			if f.Subject != tc.wantSubj {
				t.Errorf("Subject = %q, want %q", f.Subject, tc.wantSubj)
			}
			if f.Rule != pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW {
				t.Errorf("Rule = %v, want THREAT_RULE_ID_CROSS_TENANT_FLOW", f.Rule)
			}
			if len(f.Evidence.Flows) != 1 {
				t.Fatalf("Evidence.Flows = %+v, want exactly 1 flow", f.Evidence.Flows)
			}
		})
	}
}

// Replays the cross-org fence-probe incident's flow shape: two containers on
// the same backend, different tenants, exchanging a flow. This is the
// #1642 acceptance-criteria replay for the cross-tenant rule (the continuous
// form of the one-shot isolation check).
func TestCrossTenantFlowRule_IncidentReplay(t *testing.T) {
	tenants := fakeTenants(map[string]string{
		"10.10.0.5": "org-a",
		"10.10.0.9": "org-b",
	})
	ctx := RuleContext{TenantForIP: tenants}
	r := NewCrossTenantFlowRule()

	got := r.OnFlows(ctx, []netbpf.FlowRecord{{
		Saddr: beIP(10, 10, 0, 5), Daddr: beIP(10, 10, 0, 9),
		Sport: 51000, Dport: 8080, Proto: 6, Bytes: 4096, Packets: 12,
	}})

	if len(got) != 1 {
		t.Fatalf("findings = %+v, want exactly 1", got)
	}
	f := got[0]
	if f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_CRITICAL {
		t.Errorf("Severity = %v, want CRITICAL", f.Severity)
	}
	if f.TenantID != "org-a" || f.Subject != "org-b" {
		t.Errorf("TenantID/Subject = %q/%q, want org-a/org-b", f.TenantID, f.Subject)
	}
	ev := f.Evidence.Flows[0]
	if ev.SrcIP != "10.10.0.5" || ev.DstIP != "10.10.0.9" || ev.DstPort != 8080 || ev.Protocol != "tcp" {
		t.Errorf("evidence = %+v, want the replayed 5-tuple", ev)
	}
}

func TestCrossTenantFlowRule_OnDenyAndSweep_AreNoops(t *testing.T) {
	r := NewCrossTenantFlowRule()
	ctx := RuleContext{TenantForIP: fakeTenants(nil)}
	if got := r.OnDeny(ctx, netbpf.DenyEvent{}); got != nil {
		t.Errorf("OnDeny = %+v, want nil (flow-shaped rule)", got)
	}
	if got := r.Sweep(ctx, time.Time{}); got != nil {
		t.Errorf("Sweep = %+v, want nil (no window state)", got)
	}
}
