package server

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func secWriteNonAdminCtx() context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), "dev",
		[]string{"user"}, []string{auth.ScopeSecurityWrite})
}

func newPolicyServer(t *testing.T) (*ThreatDetectionServer, *responderFixture) {
	t.Helper()
	fx := newResponderFixture(t, false)
	s := NewThreatDetectionServer(nil, true, true, "")
	s.SetProcessPolicyStore(fx.policies)
	s.SetProcessResponder(fx.r)
	return s, fx
}

func TestGetProcessPolicy_NoStore_ReturnsUnavailable(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	_, err := s.GetProcessPolicy(secReadCtx(), &pb.GetProcessPolicyRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("GetProcessPolicy without a store = %v, want Unavailable", err)
	}
}

func TestGetProcessPolicy_DefaultIsBuiltinAlert(t *testing.T) {
	s, _ := newPolicyServer(t)
	resp, err := s.GetProcessPolicy(secReadCtx(), &pb.GetProcessPolicyRequest{})
	if err != nil {
		t.Fatalf("GetProcessPolicy: %v", err)
	}
	if resp.GetPolicy() != nil || resp.GetIsOverride() {
		t.Errorf("policy = %v is_override = %v, want unset/false on a fresh backend", resp.GetPolicy(), resp.GetIsOverride())
	}
	eff := resp.GetEffective()
	if eff.GetAction() != pb.ProcessAction_PROCESS_ACTION_ALERT || eff.GetThrottleAllowance() != "10%" || eff.GetTtl().AsDuration() != 24*time.Hour {
		t.Errorf("effective = %v, want built-in ALERT/10%%/24h", eff)
	}
}

func TestSetProcessPolicy_AuthAndValidation(t *testing.T) {
	s, _ := newPolicyServer(t)
	tests := []struct {
		name string
		ctx  context.Context
		req  *pb.SetProcessPolicyRequest
		want codes.Code
	}{
		{"read scope is denied", secReadCtx(), &pb.SetProcessPolicyRequest{Policy: &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_ALERT}}, codes.PermissionDenied},
		{"write scope without admin is denied", secWriteNonAdminCtx(), &pb.SetProcessPolicyRequest{Policy: &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_ALERT}}, codes.PermissionDenied},
		{"missing policy", badDestAdminCtx(), &pb.SetProcessPolicyRequest{}, codes.InvalidArgument},
		{"bad allowance", badDestAdminCtx(), &pb.SetProcessPolicyRequest{Policy: &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, ThrottleAllowance: "lots"}}, codes.InvalidArgument},
		{"clear_override without container", badDestAdminCtx(), &pb.SetProcessPolicyRequest{ClearOverride: true}, codes.InvalidArgument},
		{"valid", badDestAdminCtx(), &pb.SetProcessPolicyRequest{Policy: &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, ThrottleAllowance: "10%", Ttl: durationpb.New(time.Hour)}}, codes.OK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.SetProcessPolicy(tt.ctx, tt.req)
			if status.Code(err) != tt.want {
				t.Fatalf("SetProcessPolicy = %v, want code %v", err, tt.want)
			}
		})
	}
}

func TestSetProcessPolicy_DefaultThenOverrideThenClear(t *testing.T) {
	s, _ := newPolicyServer(t)
	ctx := badDestAdminCtx()

	resp, err := s.SetProcessPolicy(ctx, &pb.SetProcessPolicyRequest{Policy: &pb.ProcessPolicy{
		Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, ThrottleAllowance: "5%", Ttl: durationpb.New(2 * time.Hour)}})
	if err != nil {
		t.Fatalf("SetProcessPolicy default: %v", err)
	}
	if resp.GetEffective().GetAction() != pb.ProcessAction_PROCESS_ACTION_THROTTLE || resp.GetEffective().GetThrottleAllowance() != "5%" {
		t.Fatalf("effective after default = %v", resp.GetEffective())
	}

	resp, err = s.SetProcessPolicy(ctx, &pb.SetProcessPolicyRequest{Container: "box-a", Policy: &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_FREEZE}})
	if err != nil {
		t.Fatalf("SetProcessPolicy override: %v", err)
	}
	eff := resp.GetEffective()
	if eff.GetAction() != pb.ProcessAction_PROCESS_ACTION_FREEZE || eff.GetThrottleAllowance() != "5%" || eff.GetTtl().AsDuration() != 2*time.Hour {
		t.Fatalf("effective override = %v, want FREEZE inheriting 5%%/2h", eff)
	}

	got, err := s.GetProcessPolicy(secReadCtx(), &pb.GetProcessPolicyRequest{Container: "box-a"})
	if err != nil {
		t.Fatalf("GetProcessPolicy box-a: %v", err)
	}
	if !got.GetIsOverride() || got.GetPolicy().GetAction() != pb.ProcessAction_PROCESS_ACTION_FREEZE {
		t.Fatalf("GetProcessPolicy box-a = %v, want is_override with the FREEZE policy", got)
	}
	if other, _ := s.GetProcessPolicy(secReadCtx(), &pb.GetProcessPolicyRequest{Container: "box-b"}); other.GetIsOverride() || other.GetEffective().GetAction() != pb.ProcessAction_PROCESS_ACTION_THROTTLE {
		t.Fatalf("GetProcessPolicy box-b = %v, want no override and the backend default", other)
	}

	resp, err = s.SetProcessPolicy(ctx, &pb.SetProcessPolicyRequest{Container: "box-a", ClearOverride: true})
	if err != nil {
		t.Fatalf("SetProcessPolicy clear: %v", err)
	}
	if resp.GetEffective().GetAction() != pb.ProcessAction_PROCESS_ACTION_THROTTLE {
		t.Fatalf("effective after clear = %v, want the backend default", resp.GetEffective())
	}
	got, _ = s.GetProcessPolicy(secReadCtx(), &pb.GetProcessPolicyRequest{Container: "box-a"})
	if got.GetIsOverride() || got.GetPolicy() != nil {
		t.Fatalf("GetProcessPolicy box-a after clear = %v, want no override", got)
	}
}

func TestReleaseProcessAction(t *testing.T) {
	s, fx := newPolicyServer(t)
	fx.act.count["box-a"], fx.act.allow["box-a"] = "2", "200ms/100ms"
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", 0)

	if _, err := s.ReleaseProcessAction(badDestAdminCtx(), &pb.ReleaseProcessActionRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Release without container = %v, want InvalidArgument", err)
	}
	if _, err := s.ReleaseProcessAction(badDestAdminCtx(), &pb.ReleaseProcessActionRequest{Container: "box-a"}); status.Code(err) != codes.NotFound {
		t.Fatalf("Release with nothing open = %v, want NotFound", err)
	}

	f := fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
	if _, err := s.ReleaseProcessAction(secReadCtx(), &pb.ReleaseProcessActionRequest{Container: "box-a"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Release with read scope = %v, want PermissionDenied", err)
	}
	resp, err := s.ReleaseProcessAction(badDestAdminCtx(), &pb.ReleaseProcessActionRequest{Container: "box-a"})
	if err != nil {
		t.Fatalf("ReleaseProcessAction: %v", err)
	}
	got := resp.GetFinding()
	if got.GetId() != f.ID || got.GetState() != pb.FindingState_FINDING_STATE_RESOLVED {
		t.Fatalf("released finding = %v, want id %d resolved", got, f.ID)
	}
	if got.GetResponse().GetState() != pb.ResponseState_RESPONSE_STATE_RELEASED || got.GetResponse().GetReleasedBy() != "operator" {
		t.Fatalf("released finding response = %v, want RELEASED by operator", got.GetResponse())
	}
	if fx.act.allow["box-a"] != "200ms/100ms" {
		t.Fatalf("allowance after release = %q, want the recorded 200ms/100ms", fx.act.allow["box-a"])
	}
}

func TestReleaseProcessAction_NoResponder_ReturnsUnavailable(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	_, err := s.ReleaseProcessAction(badDestAdminCtx(), &pb.ReleaseProcessActionRequest{Container: "box-a"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("ReleaseProcessAction without a responder = %v, want Unavailable", err)
	}
}

func TestSetProcessPolicy_MiningBehaviorThresholds(t *testing.T) {
	cfg, err := threatdetect.NewMiningThresholdsConfig(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := newPolicyServer(t)
	s.SetMiningThresholdsConfig(cfg)
	ctx := badDestAdminCtx()
	mb := &pb.MiningBehaviorThresholds{MinCores: 2.5}

	if _, err := s.SetProcessPolicy(ctx, &pb.SetProcessPolicyRequest{Container: "box-a",
		Policy: &pb.ProcessPolicy{MiningBehavior: mb}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("override with thresholds: got %v, want InvalidArgument", err)
	}
	if _, err := s.SetProcessPolicy(ctx, &pb.SetProcessPolicyRequest{
		Policy: &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, MiningBehavior: mb}}); err != nil {
		t.Fatalf("set default with thresholds: %v", err)
	}
	if got := cfg.Effective().MinCores; got != 2.5 {
		t.Fatalf("rule thresholds MinCores = %v, want 2.5", got)
	}
	got, err := s.GetProcessPolicy(secReadCtx(), &pb.GetProcessPolicyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetPolicy().GetMiningBehavior().GetMinCores() != 2.5 {
		t.Fatalf("Get did not return thresholds: %v", got.GetPolicy())
	}
}

func TestGetProcessPolicy_EffectiveThresholds(t *testing.T) {
	tests := []struct {
		name      string
		set       *pb.MiningBehaviorThresholds
		wantCores float64
	}{
		{"nothing ever set returns the built-in defaults", nil, threatdetect.DefaultMiningMinCores},
		{"stored thresholds win over defaults", &pb.MiningBehaviorThresholds{MinCores: 3}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := threatdetect.NewMiningThresholdsConfig(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if tt.set != nil {
				if err := cfg.Set(context.Background(), tt.set); err != nil {
					t.Fatal(err)
				}
			}
			s, _ := newPolicyServer(t)
			s.SetMiningThresholdsConfig(cfg)
			resp, err := s.GetProcessPolicy(secReadCtx(), &pb.GetProcessPolicyRequest{})
			if err != nil {
				t.Fatal(err)
			}
			mb := resp.GetEffective().GetMiningBehavior()
			if mb.GetMinCores() != tt.wantCores || len(mb.GetStratumPorts()) == 0 || mb.GetWindow().AsDuration() != threatdetect.DefaultMiningWindow {
				t.Errorf("effective.mining_behavior = %v, want min_cores %v with default window/ports", mb, tt.wantCores)
			}
		})
	}
}
