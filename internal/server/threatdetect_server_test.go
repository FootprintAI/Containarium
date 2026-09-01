package server

import (
	"context"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestGetSentryStatus_Disabled(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	resp, err := s.GetSentryStatus(context.Background(), &pb.GetSentryStatusRequest{})
	if err != nil {
		t.Fatalf("GetSentryStatus: %v", err)
	}
	if resp.State != pb.SentryState_SENTRY_STATE_DISABLED {
		t.Errorf("state = %v, want DISABLED", resp.State)
	}
	if resp.Reason == "" {
		t.Error("reason is empty, want an explanation")
	}
}

// Enabled but no eBPF object loaded: must report UNAVAILABLE with a reason,
// never silently "no findings" — the #1640 acceptance criterion.
func TestGetSentryStatus_UnavailableWithoutEBPF(t *testing.T) {
	s := NewThreatDetectionServer(nil, true, false, "eBPF object not loaded (set CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT)")
	resp, err := s.GetSentryStatus(context.Background(), &pb.GetSentryStatusRequest{})
	if err != nil {
		t.Fatalf("GetSentryStatus: %v", err)
	}
	if resp.State != pb.SentryState_SENTRY_STATE_UNAVAILABLE {
		t.Errorf("state = %v, want UNAVAILABLE", resp.State)
	}
	if resp.Reason != "eBPF object not loaded (set CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT)" {
		t.Errorf("reason = %q, want the wired unavailableReason", resp.Reason)
	}
}

func TestGetSentryStatus_Degraded(t *testing.T) {
	engine := threatdetect.NewEngine(&fakeFindingSink{}, "backend-1", true /* degraded */, nil, nil)
	s := NewThreatDetectionServer(engine, true, true, "")
	resp, err := s.GetSentryStatus(context.Background(), &pb.GetSentryStatusRequest{})
	if err != nil {
		t.Fatalf("GetSentryStatus: %v", err)
	}
	if resp.State != pb.SentryState_SENTRY_STATE_DEGRADED {
		t.Errorf("state = %v, want DEGRADED", resp.State)
	}
	if resp.Reason == "" {
		t.Error("reason is empty, want an explanation of the missing persistence")
	}
}

func TestGetSentryStatus_OKWithRuleHealth(t *testing.T) {
	engine := threatdetect.NewEngine(&fakeFindingSink{}, "backend-1", false, nil, nil)
	engine.Register(&fakeRule{id: pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION})
	s := NewThreatDetectionServer(engine, true, true, "")

	resp, err := s.GetSentryStatus(context.Background(), &pb.GetSentryStatusRequest{})
	if err != nil {
		t.Fatalf("GetSentryStatus: %v", err)
	}
	if resp.State != pb.SentryState_SENTRY_STATE_OK {
		t.Errorf("state = %v, want OK", resp.State)
	}
	if len(resp.Rules) != 1 || resp.Rules[0].Rule != pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION || !resp.Rules[0].Healthy {
		t.Errorf("rules = %+v, want one healthy BAD_DESTINATION entry", resp.Rules)
	}
}

func TestListBadDestinations_NoRule_ReturnsUnavailable(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	if _, err := s.ListBadDestinations(context.Background(), &pb.ListBadDestinationsRequest{}); err == nil {
		t.Fatal("ListBadDestinations with no rule wired should error, got nil")
	}
}

func TestAddThenListBadDestination(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	rule, err := threatdetect.NewBadDestinationRule(context.Background(), nil)
	if err != nil {
		t.Fatalf("NewBadDestinationRule: %v", err)
	}
	s.SetBadDestinationRule(rule)

	addResp, err := s.AddBadDestination(context.Background(), &pb.AddBadDestinationRequest{Cidr: "192.0.2.55/32", Label: "test entry"})
	if err != nil {
		t.Fatalf("AddBadDestination: %v", err)
	}
	if addResp.GetEntry().GetCidr() != "192.0.2.55/32" || addResp.GetEntry().GetSource() != "operator" {
		t.Errorf("AddBadDestination entry = %+v, want cidr=192.0.2.55/32 source=operator", addResp.GetEntry())
	}

	listResp, err := s.ListBadDestinations(context.Background(), &pb.ListBadDestinationsRequest{})
	if err != nil {
		t.Fatalf("ListBadDestinations: %v", err)
	}
	found := false
	for _, e := range listResp.GetEntries() {
		if e.GetCidr() == "192.0.2.55/32" {
			found = true
		}
	}
	if !found {
		t.Errorf("ListBadDestinations = %+v, want the just-added entry", listResp.GetEntries())
	}
}

func TestAddBadDestination_MissingCidr(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	rule, err := threatdetect.NewBadDestinationRule(context.Background(), nil)
	if err != nil {
		t.Fatalf("NewBadDestinationRule: %v", err)
	}
	s.SetBadDestinationRule(rule)

	if _, err := s.AddBadDestination(context.Background(), &pb.AddBadDestinationRequest{Label: "no cidr"}); err == nil {
		t.Fatal("AddBadDestination with no cidr should error, got nil")
	}
}

func TestRemoveBadDestination_NotFound(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	rule, err := threatdetect.NewBadDestinationRule(context.Background(), nil)
	if err != nil {
		t.Fatalf("NewBadDestinationRule: %v", err)
	}
	s.SetBadDestinationRule(rule)

	if _, err := s.RemoveBadDestination(context.Background(), &pb.RemoveBadDestinationRequest{Cidr: "192.0.2.99/32"}); err == nil {
		t.Fatal("RemoveBadDestination on a never-added entry should error, got nil")
	}
}

func TestRemoveBadDestination_RoundTrip(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	rule, err := threatdetect.NewBadDestinationRule(context.Background(), nil)
	if err != nil {
		t.Fatalf("NewBadDestinationRule: %v", err)
	}
	s.SetBadDestinationRule(rule)

	if _, err := s.AddBadDestination(context.Background(), &pb.AddBadDestinationRequest{Cidr: "192.0.2.55/32", Label: "temp"}); err != nil {
		t.Fatalf("AddBadDestination: %v", err)
	}
	if _, err := s.RemoveBadDestination(context.Background(), &pb.RemoveBadDestinationRequest{Cidr: "192.0.2.55/32"}); err != nil {
		t.Fatalf("RemoveBadDestination: %v", err)
	}
	listResp, err := s.ListBadDestinations(context.Background(), &pb.ListBadDestinationsRequest{})
	if err != nil {
		t.Fatalf("ListBadDestinations: %v", err)
	}
	for _, e := range listResp.GetEntries() {
		if e.GetCidr() == "192.0.2.55/32" {
			t.Errorf("entry still listed after removal: %+v", e)
		}
	}
}

// fakeFindingSink and fakeRule are minimal threatdetect.FindingSink /
// threatdetect.Rule test doubles — this file only needs an Engine to exist
// and report status, not to actually detect anything.
type fakeFindingSink struct{}

func (fakeFindingSink) Upsert(ctx context.Context, f *threatdetect.Finding) (*threatdetect.Finding, error) {
	return f, nil
}

type fakeRule struct{ id pb.ThreatRuleId }

func (r *fakeRule) ID() pb.ThreatRuleId { return r.id }
func (r *fakeRule) OnFlows(threatdetect.RuleContext, []netbpf.FlowRecord) []threatdetect.RawFinding {
	return nil
}
func (r *fakeRule) OnDeny(threatdetect.RuleContext, netbpf.DenyEvent) []threatdetect.RawFinding {
	return nil
}
func (r *fakeRule) Sweep(threatdetect.RuleContext, time.Time) []threatdetect.RawFinding {
	return nil
}
