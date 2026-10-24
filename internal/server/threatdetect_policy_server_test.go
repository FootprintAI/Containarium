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

// #2820: releasing box A of a finding box B still holds. The response keeps
// the finding open, the finding reads B's APPLIED (a FREEZE here, so the
// two records cannot be mistaken for each other), and `released` is A's own
// THROTTLE RELEASED record, which the CLI and MCP report.
func TestReleaseProcessAction_SharedFindingReturnsTheBoxRecord(t *testing.T) {
	s, fx := newPolicyServer(t)
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
	if err := fx.policies.SetOverride(context.Background(), "box-b", &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_FREEZE}); err != nil {
		t.Fatal(err)
	}
	fx.fireSignature(t, "box-a", 0)
	fx.fireSignature(t, "box-b", 0)
	resp, err := s.ReleaseProcessAction(badDestAdminCtx(), &pb.ReleaseProcessActionRequest{Container: "box-a"})
	if err != nil {
		t.Fatalf("ReleaseProcessAction: %v", err)
	}
	if !resp.GetFindingKeptOpen() || resp.GetFinding().GetState() != pb.FindingState_FINDING_STATE_OPEN {
		t.Fatalf("release of box-a = %v, want the finding kept open", resp)
	}
	if r := resp.GetFinding().GetResponse(); r.GetState() != pb.ResponseState_RESPONSE_STATE_APPLIED || r.GetAction() != pb.ProcessAction_PROCESS_ACTION_FREEZE || r.GetContainer() != "box-b" {
		t.Errorf("finding response = %v, want box-b's FREEZE APPLIED", r)
	}
	if r := resp.GetReleased(); r.GetState() != pb.ResponseState_RESPONSE_STATE_RELEASED || r.GetAction() != pb.ProcessAction_PROCESS_ACTION_THROTTLE ||
		r.GetContainer() != "box-a" || r.GetReleasedBy() != "operator" {
		t.Errorf("released = %v, want box-a's THROTTLE RELEASED by operator", r)
	}
	resp, err = s.ReleaseProcessAction(badDestAdminCtx(), &pb.ReleaseProcessActionRequest{Container: "box-b"})
	if err != nil {
		t.Fatalf("ReleaseProcessAction box-b: %v", err)
	}
	if resp.GetFindingKeptOpen() || resp.GetFinding().GetState() != pb.FindingState_FINDING_STATE_RESOLVED ||
		resp.GetReleased().GetContainer() != "box-b" || resp.GetFinding().GetResponse().GetContainer() != "box-b" {
		t.Errorf("release of box-b = %v, want resolved with box-b's release", resp)
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

// A SetProcessPolicy that carries only some fields must change only those
// fields. Tuning the mining thresholds used to replace the stored policy with
// an empty one, silently wiping the configured action, allowance and TTL, and
// the result depended on the order of two `process-policy set` calls (#2675).
func TestSetProcessPolicy_PartialUpdatesKeepTheRest(t *testing.T) {
	throttle := &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, ThrottleAllowance: "20%", Ttl: durationpb.New(2 * time.Hour)}
	thresholds := &pb.ProcessPolicy{MiningBehavior: &pb.MiningBehaviorThresholds{Window: durationpb.New(5 * time.Minute)}}
	freezeOnly := &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_FREEZE}
	for _, container := range []string{"", "box-a"} {
		name := "backend default"
		if container != "" {
			name = "container override"
		}
		t.Run(name+"/thresholds after action keep the action", func(t *testing.T) {
			s, cfg := newPolicyServerWithThresholds(t)
			mustSet(t, s, container, throttle)
			if container != "" {
				// thresholds are backend-wide: set them at the default level
				mustSet(t, s, "", thresholds)
			} else {
				mustSet(t, s, container, thresholds)
			}
			eff := mustEffective(t, s, container)
			if eff.GetAction() != pb.ProcessAction_PROCESS_ACTION_THROTTLE || eff.GetThrottleAllowance() != "20%" || eff.GetTtl().AsDuration() != 2*time.Hour {
				t.Fatalf("effective after thresholds-only set = %v, want THROTTLE/20%%/2h kept", eff)
			}
			if cfg.Effective().Window != 5*time.Minute {
				t.Errorf("window = %v, want 5m applied", cfg.Effective().Window)
			}
		})
		t.Run(name+"/action after thresholds keeps the thresholds", func(t *testing.T) {
			s, cfg := newPolicyServerWithThresholds(t)
			mustSet(t, s, "", thresholds)
			mustSet(t, s, container, throttle)
			if cfg.Effective().Window != 5*time.Minute {
				t.Errorf("window = %v, want 5m kept after an action-only set", cfg.Effective().Window)
			}
		})
		t.Run(name+"/changing only the action keeps allowance and ttl", func(t *testing.T) {
			s, _ := newPolicyServerWithThresholds(t)
			mustSet(t, s, container, throttle)
			mustSet(t, s, container, freezeOnly)
			eff := mustEffective(t, s, container)
			if eff.GetAction() != pb.ProcessAction_PROCESS_ACTION_FREEZE || eff.GetThrottleAllowance() != "20%" || eff.GetTtl().AsDuration() != 2*time.Hour {
				t.Fatalf("effective = %v, want FREEZE with allowance 20%% and ttl 2h kept", eff)
			}
		})
	}
	t.Run("thresholds only on a fresh backend does not create a stored policy", func(t *testing.T) {
		s, _ := newPolicyServerWithThresholds(t)
		mustSet(t, s, "", thresholds)
		got, err := s.GetProcessPolicy(secReadCtx(), &pb.GetProcessPolicyRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if got.GetPolicy().GetAction() != pb.ProcessAction_PROCESS_ACTION_UNSPECIFIED {
			t.Errorf("stored action = %v, want unset", got.GetPolicy().GetAction())
		}
	})
}

func newPolicyServerWithThresholds(t *testing.T) (*ThreatDetectionServer, *threatdetect.MiningThresholdsConfig) {
	t.Helper()
	cfg, err := threatdetect.NewMiningThresholdsConfig(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := newPolicyServer(t)
	s.SetMiningThresholdsConfig(cfg)
	return s, cfg
}

func mustSet(t *testing.T, s *ThreatDetectionServer, container string, p *pb.ProcessPolicy) {
	t.Helper()
	if _, err := s.SetProcessPolicy(badDestAdminCtx(), &pb.SetProcessPolicyRequest{Container: container, Policy: p}); err != nil {
		t.Fatalf("SetProcessPolicy(%q, %v): %v", container, p, err)
	}
}

func mustEffective(t *testing.T, s *ThreatDetectionServer, container string) *pb.ProcessPolicy {
	t.Helper()
	resp, err := s.GetProcessPolicy(secReadCtx(), &pb.GetProcessPolicyRequest{Container: container})
	if err != nil {
		t.Fatalf("GetProcessPolicy(%q): %v", container, err)
	}
	return resp.GetEffective()
}
