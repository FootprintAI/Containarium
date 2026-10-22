package server

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2348: UpdateContainerACL used to build the custom rule set and then throw
// it away (EnsureACLForContainer was called with a preset), and mapped
// CUSTOM/UNSPECIFIED to full-isolation silently. #2359: ingress is owned by
// the tenant network guard, so the per-container ACL carries egress only.
// The config an update writes is a pure function of the request.
func TestACLConfigFromRequest(t *testing.T) {
	const proxyIP, bridge = "10.100.0.2", "10.100.0.0/24"

	tests := []struct {
		name     string
		req      *pb.UpdateContainerACLRequest
		wantCode codes.Code // codes.OK means no error
		check    func(t *testing.T, cfg incus.ACLConfig)
	}{
		{
			name: "custom egress rules are applied verbatim",
			req: &pb.UpdateContainerACLRequest{
				Username: "alice",
				Preset:   pb.ACLPreset_ACL_PRESET_CUSTOM,
				EgressRules: []*pb.ACLRule{{
					Action: pb.ACLAction_ACL_ACTION_DROP, Destination: "10.100.0.0/24", Description: "no bridge",
				}},
			},
			check: func(t *testing.T, cfg incus.ACLConfig) {
				if cfg.Name != "acl-alice" {
					t.Errorf("name = %q, want acl-alice", cfg.Name)
				}
				if len(cfg.IngressRules) != 0 || len(cfg.EgressRules) != 1 {
					t.Fatalf("rules = %d ingress / %d egress, want 0/1", len(cfg.IngressRules), len(cfg.EgressRules))
				}
				if out := cfg.EgressRules[0]; out.Action != "drop" || out.Destination != "10.100.0.0/24" || out.Description != "no bridge" {
					t.Errorf("egress rule not verbatim: %+v", out)
				}
			},
		},
		{
			// #2359: a per-container ingress allow would be evaluated next to
			// the guard's ACL and could re-open what it closed.
			name: "custom ingress rules are refused, pointing at allow_from_tenants",
			req: &pb.UpdateContainerACLRequest{
				Username: "alice",
				Preset:   pb.ACLPreset_ACL_PRESET_CUSTOM,
				IngressRules: []*pb.ACLRule{{
					Action: pb.ACLAction_ACL_ACTION_ALLOW, Source: "0.0.0.0/0", DestinationPort: "5432", Protocol: "tcp",
				}},
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "unspecified preset is rejected, never substituted",
			req:      &pb.UpdateContainerACLRequest{Username: "alice", Preset: pb.ACLPreset_ACL_PRESET_UNSPECIFIED},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "a named preset expands with the container's name, egress half only",
			req:  &pb.UpdateContainerACLRequest{Username: "alice", Preset: pb.ACLPreset_ACL_PRESET_HTTP_ONLY},
			check: func(t *testing.T, cfg incus.ACLConfig) {
				want := incus.GetPresetACL(incus.ACLPresetHTTPOnly, proxyIP, bridge)
				if cfg.Name != "acl-alice" {
					t.Errorf("name = %q, want acl-alice", cfg.Name)
				}
				if len(cfg.IngressRules) != 0 || len(cfg.EgressRules) != len(want.EgressRules) {
					t.Errorf("preset rules differ: got %d/%d want 0/%d", len(cfg.IngressRules), len(cfg.EgressRules), len(want.EgressRules))
				}
			},
		},
		{
			name: "custom with no rules is a valid empty rule set, not a preset",
			req:  &pb.UpdateContainerACLRequest{Username: "alice", Preset: pb.ACLPreset_ACL_PRESET_CUSTOM},
			check: func(t *testing.T, cfg incus.ACLConfig) {
				if len(cfg.IngressRules) != 0 || len(cfg.EgressRules) != 0 {
					t.Errorf("expected no rules, got %+v", cfg)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := aclConfigFromRequest(tt.req, proxyIP, bridge)
			if tt.wantCode != codes.OK {
				if status.Code(err) != tt.wantCode {
					t.Fatalf("err = %v, want code %v", err, tt.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tt.check(t, cfg)
		})
	}
}

// presetFromProto has no fallback case: every enum value either maps to an
// Incus preset or is reported as not-a-preset. Enumerating the descriptor
// means a new enum value fails this test until it is mapped deliberately.
func TestPresetFromProto_exhaustive(t *testing.T) {
	values := pb.ACLPreset(0).Descriptor().Values()
	for i := 0; i < values.Len(); i++ {
		v := pb.ACLPreset(values.Get(i).Number())
		preset, ok := presetFromProto(v)
		switch v {
		case pb.ACLPreset_ACL_PRESET_UNSPECIFIED, pb.ACLPreset_ACL_PRESET_CUSTOM:
			if ok {
				t.Errorf("%v: expected ok=false, got preset %q", v, preset)
			}
		default:
			if !ok || preset == "" {
				t.Errorf("%v: expected a mapped preset, got ok=%v preset=%q", v, ok, preset)
			}
		}
	}
	if values.Len() < 4 {
		t.Fatalf("ACLPreset has %d values, expected at least 4", values.Len())
	}
}
