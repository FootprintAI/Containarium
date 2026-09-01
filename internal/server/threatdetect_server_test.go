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
