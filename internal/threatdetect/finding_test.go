package threatdetect

import (
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestEvidence_Capped(t *testing.T) {
	tests := []struct {
		name       string
		flows      int
		denies     int
		wantFlows  int
		wantDenies int
	}{
		{name: "under cap", flows: 3, denies: 2, wantFlows: 3, wantDenies: 2},
		{name: "at cap", flows: EvidenceCap, denies: EvidenceCap, wantFlows: EvidenceCap, wantDenies: EvidenceCap},
		{name: "over cap keeps the most recent", flows: EvidenceCap + 7, denies: EvidenceCap + 1, wantFlows: EvidenceCap, wantDenies: EvidenceCap},
		{name: "empty", flows: 0, denies: 0, wantFlows: 0, wantDenies: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e Evidence
			for i := 0; i < tt.flows; i++ {
				e.Flows = append(e.Flows, FlowEvidence{DstPort: uint32(i)})
			}
			for i := 0; i < tt.denies; i++ {
				e.Denies = append(e.Denies, DenyEvidence{Count: int64(i)})
			}

			got := e.Capped()
			if len(got.Flows) != tt.wantFlows {
				t.Errorf("Flows = %d, want %d", len(got.Flows), tt.wantFlows)
			}
			if len(got.Denies) != tt.wantDenies {
				t.Errorf("Denies = %d, want %d", len(got.Denies), tt.wantDenies)
			}
			// "most recent" means the tail, not an arbitrary EvidenceCap-sized slice.
			if tt.flows > EvidenceCap && int(got.Flows[len(got.Flows)-1].DstPort) != tt.flows-1 {
				t.Errorf("last kept flow DstPort = %d, want %d (the most recent)", got.Flows[len(got.Flows)-1].DstPort, tt.flows-1)
			}
		})
	}
}

func TestFinding_ToProto(t *testing.T) {
	firstSeen := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	lastSeen := firstSeen.Add(5 * time.Minute)

	f := &Finding{
		ID:        42,
		Rule:      pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW,
		Severity:  pb.ThreatSeverity_THREAT_SEVERITY_CRITICAL,
		TenantID:  "tenant-a",
		Container: "c1",
		BackendID: "backend-1",
		Subject:   "tenant-b",
		State:     FindingStateOpen,
		Count:     3,
		Evidence: Evidence{
			Flows:  []FlowEvidence{{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: "tcp"}},
			Denies: []DenyEvidence{{DstIP: "10.0.0.2", Reason: "policy", Count: 5}},
		},
		FirstSeen: firstSeen,
		LastSeen:  lastSeen,
	}

	got := f.ToProto()

	if got.Id != 42 {
		t.Errorf("Id = %d, want 42", got.Id)
	}
	if got.Rule != pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW {
		t.Errorf("Rule = %v, want THREAT_RULE_ID_CROSS_TENANT_FLOW", got.Rule)
	}
	if got.Severity != pb.ThreatSeverity_THREAT_SEVERITY_CRITICAL {
		t.Errorf("Severity = %v, want THREAT_SEVERITY_CRITICAL", got.Severity)
	}
	if got.State != pb.FindingState_FINDING_STATE_OPEN {
		t.Errorf("State = %v, want FINDING_STATE_OPEN", got.State)
	}
	if got.TenantId != "tenant-a" || got.Container != "c1" || got.BackendId != "backend-1" || got.Subject != "tenant-b" {
		t.Errorf("identity fields = %+v, want tenant-a/c1/backend-1/tenant-b", got)
	}
	if got.Count != 3 {
		t.Errorf("Count = %d, want 3", got.Count)
	}
	if len(got.Evidence.Flows) != 1 || got.Evidence.Flows[0].SrcIp != "10.0.0.1" {
		t.Fatalf("Evidence.Flows = %+v", got.Evidence.Flows)
	}
	if len(got.Evidence.Denies) != 1 || got.Evidence.Denies[0].Reason != "policy" {
		t.Fatalf("Evidence.Denies = %+v", got.Evidence.Denies)
	}
	if !got.FirstSeen.AsTime().Equal(firstSeen) {
		t.Errorf("FirstSeen = %v, want %v", got.FirstSeen.AsTime(), firstSeen)
	}
	if !got.LastSeen.AsTime().Equal(lastSeen) {
		t.Errorf("LastSeen = %v, want %v", got.LastSeen.AsTime(), lastSeen)
	}
}

func TestFinding_ToProto_ResolvedState(t *testing.T) {
	f := &Finding{State: FindingStateResolved}
	got := f.ToProto()
	if got.State != pb.FindingState_FINDING_STATE_RESOLVED {
		t.Errorf("State = %v, want FINDING_STATE_RESOLVED", got.State)
	}
}

func TestFinding_ToProto_ZeroTimeOmitted(t *testing.T) {
	f := &Finding{}
	got := f.ToProto()
	if got.FirstSeen != nil {
		t.Errorf("FirstSeen = %v, want nil for a zero time.Time", got.FirstSeen)
	}
	if got.LastSeen != nil {
		t.Errorf("LastSeen = %v, want nil for a zero time.Time", got.LastSeen)
	}
}

// A deduped repeat may raise an open finding's severity, never lower it.
func TestMaxSeverity(t *testing.T) {
	const (
		unspec = pb.ThreatSeverity_THREAT_SEVERITY_UNSPECIFIED
		medium = pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM
		high   = pb.ThreatSeverity_THREAT_SEVERITY_HIGH
	)
	for _, c := range []struct{ a, b, want pb.ThreatSeverity }{
		{medium, high, high},
		{high, medium, high},
		{medium, medium, medium},
		{unspec, medium, medium},
		{medium, unspec, medium},
	} {
		if got := maxSeverity(c.a, c.b); got != c.want {
			t.Errorf("maxSeverity(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// Config evidence is a state snapshot: re-merging an identical entry (a box
// that stays permissive, pass after pass) must not grow the list, while a
// changed entry is still added.
func TestEvidenceMerged_ConfigEvidenceIsDeduplicated(t *testing.T) {
	a := ConfigEvidence{Path: "/etc/ssh/sshd_config.d/0.conf", Directive: "PasswordAuthentication", Value: "yes"}
	b := ConfigEvidence{Path: "/etc/ssh/sshd_config.d/0.conf", Directive: "PasswordAuthentication", Value: "yes", Remediated: true}

	got := Evidence{Configs: []ConfigEvidence{a}}
	for i := 0; i < 5; i++ {
		got = got.merged(Evidence{Configs: []ConfigEvidence{a}})
	}
	if len(got.Configs) != 1 {
		t.Fatalf("5 identical repeats left %d entries, want 1: %+v", len(got.Configs), got.Configs)
	}

	got = got.merged(Evidence{Configs: []ConfigEvidence{a, b, b}})
	if len(got.Configs) != 2 || got.Configs[1] != b {
		t.Fatalf("a changed entry must be added exactly once, got %+v", got.Configs)
	}
}
