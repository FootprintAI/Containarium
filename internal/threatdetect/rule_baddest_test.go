package threatdetect

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func testRuleContext(tenantByIP map[string]string) RuleContext {
	return RuleContext{
		TenantForIP: func(ip netip.Addr) (string, bool) {
			t, ok := tenantByIP[ip.String()]
			return t, ok
		},
	}
}

func flow(src, dst string) netbpf.FlowRecord {
	sAddr := netip.MustParseAddr(src).As4()
	dAddr := netip.MustParseAddr(dst).As4()
	return netbpf.FlowRecord{
		Saddr:   beUint32(sAddr),
		Daddr:   beUint32(dAddr),
		Sport:   54321,
		Dport:   443,
		Proto:   6, // tcp
		Packets: 42,
		Bytes:   4096,
	}
}

func TestBadDestinationRule_ExactIPHit(t *testing.T) {
	r := newBadDestinationRuleForTest(t, []BadDestinationEntry{
		{CIDR: "198.51.100.7/32", Label: "known miner", Source: "baseline"},
	}, nil)
	ctx := testRuleContext(map[string]string{"10.0.0.5": "tenant-a"})

	findings := r.OnFlows(ctx, []netbpf.FlowRecord{flow("10.0.0.5", "198.51.100.7")})

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Rule != pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION {
		t.Errorf("Rule = %v, want BAD_DESTINATION", f.Rule)
	}
	if f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_HIGH {
		t.Errorf("Severity = %v, want HIGH", f.Severity)
	}
	if f.TenantID != "tenant-a" {
		t.Errorf("TenantID = %q, want tenant-a", f.TenantID)
	}
	if f.Subject != "198.51.100.7" {
		t.Errorf("Subject = %q, want the destination IP", f.Subject)
	}
	if len(f.Evidence.Flows) != 1 || f.Evidence.Flows[0].DstIP != "198.51.100.7" {
		t.Errorf("Evidence.Flows = %+v, want one flow to the bad destination", f.Evidence.Flows)
	}
}

func TestBadDestinationRule_CIDRHit(t *testing.T) {
	r := newBadDestinationRuleForTest(t, []BadDestinationEntry{
		{CIDR: "198.51.100.0/24", Label: "known mining range", Source: "baseline"},
	}, nil)
	ctx := testRuleContext(map[string]string{"10.0.0.5": "tenant-a"})

	findings := r.OnFlows(ctx, []netbpf.FlowRecord{flow("10.0.0.5", "198.51.100.200")})

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (CIDR should match)", len(findings))
	}
}

func TestBadDestinationRule_Miss(t *testing.T) {
	r := newBadDestinationRuleForTest(t, []BadDestinationEntry{
		{CIDR: "198.51.100.0/24", Label: "known mining range", Source: "baseline"},
	}, nil)
	ctx := testRuleContext(map[string]string{"10.0.0.5": "tenant-a"})

	findings := r.OnFlows(ctx, []netbpf.FlowRecord{flow("10.0.0.5", "8.8.8.8")})

	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 for a destination not on the list", len(findings))
	}
}

func TestBadDestinationRule_UnknownSourceIP_StillFiresWithEmptyTenant(t *testing.T) {
	// Design doc: a rule must never guess at an unknown IP's tenant — but an
	// unresolved source tenant shouldn't suppress a HIGH finding about a
	// destination that IS known-bad; the operator can still see the flow.
	r := newBadDestinationRuleForTest(t, []BadDestinationEntry{
		{CIDR: "198.51.100.7/32", Label: "known miner", Source: "baseline"},
	}, nil)
	ctx := testRuleContext(nil) // no IP resolves

	findings := r.OnFlows(ctx, []netbpf.FlowRecord{flow("10.0.0.5", "198.51.100.7")})

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].TenantID != "" {
		t.Errorf("TenantID = %q, want empty for an unresolved source IP", findings[0].TenantID)
	}
}

func TestBadDestinationRule_OperatorAddedEntry(t *testing.T) {
	r := newBadDestinationRuleForTest(t, nil, nil)
	ctx := testRuleContext(map[string]string{"10.0.0.5": "tenant-a"})

	// Not on the (empty) baseline list yet.
	if findings := r.OnFlows(ctx, []netbpf.FlowRecord{flow("10.0.0.5", "192.0.2.55")}); len(findings) != 0 {
		t.Fatalf("got %d findings before adding the entry, want 0", len(findings))
	}

	if _, err := r.AddDestination(context.Background(), "192.0.2.55/32", "operator-flagged host"); err != nil {
		t.Fatalf("AddDestination: %v", err)
	}

	findings := r.OnFlows(ctx, []netbpf.FlowRecord{flow("10.0.0.5", "192.0.2.55")})
	if len(findings) != 1 {
		t.Fatalf("got %d findings after adding the entry, want 1", len(findings))
	}
}

func TestBadDestinationRule_RemoveOperatorEntry(t *testing.T) {
	r := newBadDestinationRuleForTest(t, nil, nil)
	ctx := testRuleContext(map[string]string{"10.0.0.5": "tenant-a"})

	if _, err := r.AddDestination(context.Background(), "192.0.2.55/32", "operator-flagged host"); err != nil {
		t.Fatalf("AddDestination: %v", err)
	}
	if err := r.RemoveDestination(context.Background(), "192.0.2.55/32"); err != nil {
		t.Fatalf("RemoveDestination: %v", err)
	}

	findings := r.OnFlows(ctx, []netbpf.FlowRecord{flow("10.0.0.5", "192.0.2.55")})
	if len(findings) != 0 {
		t.Fatalf("got %d findings after removal, want 0", len(findings))
	}
}

func TestBadDestinationRule_RemoveBaselineEntry_Errors(t *testing.T) {
	r := newBadDestinationRuleForTest(t, []BadDestinationEntry{
		{CIDR: "198.51.100.7/32", Label: "known miner", Source: "baseline"},
	}, nil)

	err := r.RemoveDestination(context.Background(), "198.51.100.7/32")
	if err == nil {
		t.Fatal("RemoveDestination on a baseline entry should error, got nil")
	}
}

func TestBadDestinationRule_ListMergesBaselineAndOperator(t *testing.T) {
	r := newBadDestinationRuleForTest(t, []BadDestinationEntry{
		{CIDR: "198.51.100.7/32", Label: "known miner", Source: "baseline"},
	}, nil)
	if _, err := r.AddDestination(context.Background(), "192.0.2.55/32", "operator-flagged host"); err != nil {
		t.Fatalf("AddDestination: %v", err)
	}

	entries := r.ListDestinations()
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (1 baseline + 1 operator)", len(entries))
	}
	bySource := map[string]int{}
	for _, e := range entries {
		bySource[e.Source]++
	}
	if bySource["baseline"] != 1 || bySource["operator"] != 1 {
		t.Errorf("entries by source = %+v, want 1 baseline + 1 operator", bySource)
	}
}

func TestBadDestinationRule_ListReload(t *testing.T) {
	r := newBadDestinationRuleForTest(t, nil, nil)
	ctx := testRuleContext(map[string]string{"10.0.0.5": "tenant-a"})

	if findings := r.OnFlows(ctx, []netbpf.FlowRecord{flow("10.0.0.5", "192.0.2.99")}); len(findings) != 0 {
		t.Fatalf("got %d findings before reload, want 0", len(findings))
	}
	if _, err := r.AddDestination(context.Background(), "192.0.2.99/32", "added live"); err != nil {
		t.Fatalf("AddDestination: %v", err)
	}
	// The matcher must reflect the addition immediately (list reload without
	// a daemon rebuild), not just on the next process start.
	if findings := r.OnFlows(ctx, []netbpf.FlowRecord{flow("10.0.0.5", "192.0.2.99")}); len(findings) != 1 {
		t.Fatalf("got %d findings after reload, want 1", len(findings))
	}
}

func TestBadDestinationRule_MiningIncidentReplay_RaisesHighFinding(t *testing.T) {
	// Replays the incident's flow shape: a persistent TLS 5-tuple to a
	// listed pool. The #1641 acceptance test.
	r := newBadDestinationRuleForTest(t, []BadDestinationEntry{
		{CIDR: "203.0.113.10/32", Label: "known mining pool", Source: "baseline"},
	}, nil)
	ctx := testRuleContext(map[string]string{"10.0.0.9": "tenant-mining-victim"})

	incidentFlow := netbpf.FlowRecord{
		Saddr:   beUint32(netip.MustParseAddr("10.0.0.9").As4()),
		Daddr:   beUint32(netip.MustParseAddr("203.0.113.10").As4()),
		Sport:   51000,
		Dport:   443,
		Proto:   6,
		Packets: 260000, // sustained mining traffic, not a handshake blip
		Bytes:   80_000_000,
	}

	findings := r.OnFlows(ctx, []netbpf.FlowRecord{incidentFlow})

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_HIGH {
		t.Errorf("Severity = %v, want HIGH", f.Severity)
	}
	if f.TenantID != "tenant-mining-victim" {
		t.Errorf("TenantID = %q, want tenant-mining-victim", f.TenantID)
	}
	if f.Subject != "203.0.113.10" {
		t.Errorf("Subject = %q, want the mining pool IP", f.Subject)
	}
}

func TestBadDestinationRule_OnDenyAndSweep_AreNoop(t *testing.T) {
	r := newBadDestinationRuleForTest(t, nil, nil)
	if got := r.OnDeny(testRuleContext(nil), netbpf.DenyEvent{}); got != nil {
		t.Errorf("OnDeny = %v, want nil (this rule only evaluates flows)", got)
	}
	if got := r.Sweep(testRuleContext(nil), timeNowForTest()); got != nil {
		t.Errorf("Sweep = %v, want nil (this rule has no time-window state)", got)
	}
}

func TestBadDestinationRule_ID(t *testing.T) {
	r := newBadDestinationRuleForTest(t, nil, nil)
	if r.ID() != pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION {
		t.Errorf("ID() = %v, want THREAT_RULE_ID_BAD_DESTINATION", r.ID())
	}
}

// newBadDestinationRuleForTest builds a rule directly from baseline/operator
// entries, bypassing the embedded YAML and DaemonConfigStore — a nil store
// (in-memory only) is exactly what unit tests want.
func newBadDestinationRuleForTest(t *testing.T, baseline, operator []BadDestinationEntry) *BadDestinationRule {
	t.Helper()
	r := &BadDestinationRule{baseline: baseline, operator: operator}
	if err := r.rebuildMatcherLocked(); err != nil {
		t.Fatalf("rebuildMatcherLocked: %v", err)
	}
	return r
}

// beUint32 packs a 4-byte IPv4 address (as netip.Addr.As4() returns) into
// the uint32 that FlowRecord.Saddr/Daddr carry — the exact inverse of
// netbpf's unexported ipFromBE, which decodes via
// binary.NativeEndian.PutUint32. Using NativeEndian here too (not a
// hardcoded big-endian pack) keeps the round-trip correct regardless of
// host architecture.
func beUint32(b [4]byte) uint32 {
	return binary.NativeEndian.Uint32(b[:])
}

func timeNowForTest() time.Time { return time.Unix(1_700_000_000, 0) }
