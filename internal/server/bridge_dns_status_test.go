package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/bridgedns"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2188: the bridge DNS reconciler's last pass, as the status RPC reports it.
// The state is a proto enum, never a string, and derived in one pure function
// so every combination of reconciler fields has exactly one answer.

func TestBridgeDNSStatusResponse(t *testing.T) {
	pass := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	applied := pass.Add(-time.Minute)
	cases := []struct {
		name       string
		in         bridgedns.Status
		wantState  pb.BridgeDNSState
		wantReason string // exact; "" means must be empty
		wantAnyRsn bool   // reason must be non-empty but is free text
	}{
		{
			name:       "no pass has finished yet",
			in:         bridgedns.Status{Bridge: "incusbr0"},
			wantState:  pb.BridgeDNSState_BRIDGE_DNS_STATE_PENDING,
			wantAnyRsn: true,
		},
		{
			name:      "in sync",
			in:        bridgedns.Status{Bridge: "incusbr0", CaddyIP: "10.0.3.5", Desired: "d", Current: "d", InSync: true, LastPass: pass, LastApplied: applied, DriftCount: 2},
			wantState: pb.BridgeDNSState_BRIDGE_DNS_STATE_IN_SYNC,
		},
		{
			name:       "degraded carries the last error as the reason",
			in:         bridgedns.Status{Bridge: "incusbr0", LastPass: pass, LastError: "bridgedns: write incusbr0.raw.dnsmasq: permission denied", DriftCount: 1},
			wantState:  pb.BridgeDNSState_BRIDGE_DNS_STATE_DEGRADED,
			wantReason: "bridgedns: write incusbr0.raw.dnsmasq: permission denied",
		},
		{
			name:       "not in sync and no error is still degraded, never in sync",
			in:         bridgedns.Status{Bridge: "incusbr0", LastPass: pass},
			wantState:  pb.BridgeDNSState_BRIDGE_DNS_STATE_DEGRADED,
			wantAnyRsn: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bridgeDNSStatusResponse(tc.in)
			if got.State != tc.wantState {
				t.Fatalf("state = %v; want %v", got.State, tc.wantState)
			}
			switch {
			case tc.wantReason != "":
				if got.Reason != tc.wantReason {
					t.Errorf("reason = %q; want %q", got.Reason, tc.wantReason)
				}
			case tc.wantAnyRsn:
				if got.Reason == "" {
					t.Error("reason is empty; want an explanation")
				}
			default:
				if got.Reason != "" {
					t.Errorf("reason = %q; want empty when in sync", got.Reason)
				}
			}
			if got.Bridge != tc.in.Bridge || got.CaddyIp != tc.in.CaddyIP || got.Desired != tc.in.Desired ||
				got.Current != tc.in.Current || got.LastError != tc.in.LastError || int(got.DriftCount) != tc.in.DriftCount {
				t.Errorf("fields not copied through: %+v from %+v", got, tc.in)
			}
		})
	}

	t.Run("timestamps are unset until they exist", func(t *testing.T) {
		got := bridgeDNSStatusResponse(bridgedns.Status{})
		if got.LastPass != nil || got.LastApplied != nil {
			t.Fatalf("zero times must map to nil, got pass=%v applied=%v", got.LastPass, got.LastApplied)
		}
	})
	t.Run("timestamps are carried when set", func(t *testing.T) {
		got := bridgeDNSStatusResponse(bridgedns.Status{LastPass: pass, LastApplied: applied})
		if got.LastPass == nil || !got.LastPass.AsTime().Equal(pass) || got.LastApplied == nil || !got.LastApplied.AsTime().Equal(applied) {
			t.Fatalf("timestamps = %v / %v; want %v / %v", got.LastPass, got.LastApplied, pass, applied)
		}
	})
}

func TestGetBridgeDNSStatus_NotManagedWithoutAReconciler(t *testing.T) {
	s := &ContainerServer{}
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
	resp, err := s.GetBridgeDNSStatus(ctx, &pb.GetBridgeDNSStatusRequest{})
	if err != nil {
		t.Fatalf("GetBridgeDNSStatus: %v", err)
	}
	if resp.State != pb.BridgeDNSState_BRIDGE_DNS_STATE_NOT_MANAGED || resp.Reason == "" {
		t.Fatalf("resp = %+v; want NOT_MANAGED with a reason", resp)
	}
}

func TestGetBridgeDNSStatus_AdminOnly(t *testing.T) {
	s := &ContainerServer{}
	cases := []struct {
		name string
		ctx  context.Context
		want codes.Code
	}{
		{"no subject", context.Background(), codes.Unauthenticated},
		{"non-admin", auth.ContextWithTestSubject(context.Background(), "dev", "user"), codes.PermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.GetBridgeDNSStatus(tc.ctx, &pb.GetBridgeDNSStatusRequest{})
			if status.Code(err) != tc.want {
				t.Fatalf("code = %v (%v); want %v", status.Code(err), err, tc.want)
			}
		})
	}
}

type fakeBridgeBackend struct {
	ip, raw string
	getErr  error
}

func (f *fakeBridgeBackend) GetContainer(name string) (*incus.ContainerInfo, error) {
	if name != CoreCaddyContainer {
		return nil, errors.New("not found: " + name)
	}
	return &incus.ContainerInfo{Name: name, State: "Running", IPAddress: f.ip}, nil
}
func (f *fakeBridgeBackend) GetNetworkConfigValue(string, string) (string, error) {
	return f.raw, f.getErr
}
func (f *fakeBridgeBackend) SetNetworkConfigValue(_, _, v string) error { f.raw = v; return nil }

func newBridgeReconciler(be bridgedns.Backend) *bridgedns.Reconciler {
	return bridgedns.NewReconciler(be, bridgedns.Config{
		Bridge:         "incusbr0",
		CaddyContainer: CoreCaddyContainer,
		Render:         func(ip string) string { return "address=/example.com/" + ip },
	})
}

// End to end through the real reconciler: a stale record is repaired and the
// RPC reports the repaired state with the addresses the operator needs.
func TestGetBridgeDNSStatus_ReportsTheReconcilersLastPass(t *testing.T) {
	be := &fakeBridgeBackend{ip: "10.0.3.5", raw: "address=/example.com/10.0.3.9"}
	rec := newBridgeReconciler(be)
	s := &ContainerServer{}
	s.SetBridgeDNSReconciler(rec)
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)

	// Before any pass: pending, not a false "in sync".
	resp, err := s.GetBridgeDNSStatus(ctx, &pb.GetBridgeDNSStatusRequest{})
	if err != nil || resp.State != pb.BridgeDNSState_BRIDGE_DNS_STATE_PENDING {
		t.Fatalf("before a pass: resp=%+v err=%v; want PENDING", resp, err)
	}

	if err := rec.ReconcileOnce(ctx); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	resp, err = s.GetBridgeDNSStatus(ctx, &pb.GetBridgeDNSStatusRequest{})
	if err != nil {
		t.Fatalf("GetBridgeDNSStatus: %v", err)
	}
	if resp.State != pb.BridgeDNSState_BRIDGE_DNS_STATE_IN_SYNC || resp.CaddyIp != "10.0.3.5" ||
		resp.Current != "address=/example.com/10.0.3.5" || resp.Desired != resp.Current ||
		resp.DriftCount != 1 || resp.LastApplied == nil || resp.LastPass == nil {
		t.Fatalf("resp = %+v; want IN_SYNC on 10.0.3.5 after one repaired drift", resp)
	}
}

func TestGetBridgeDNSStatus_DegradedWhenThePassCannotConverge(t *testing.T) {
	be := &fakeBridgeBackend{ip: "10.0.3.5", getErr: errors.New("api error")}
	rec := newBridgeReconciler(be)
	s := &ContainerServer{}
	s.SetBridgeDNSReconciler(rec)
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)

	if err := rec.ReconcileOnce(ctx); err == nil {
		t.Fatal("want the reconcile error")
	}
	resp, err := s.GetBridgeDNSStatus(ctx, &pb.GetBridgeDNSStatusRequest{})
	if err != nil {
		t.Fatalf("GetBridgeDNSStatus: %v", err)
	}
	if resp.State != pb.BridgeDNSState_BRIDGE_DNS_STATE_DEGRADED || resp.LastError == "" || resp.Reason != resp.LastError {
		t.Fatalf("resp = %+v; want DEGRADED with the error as the reason", resp)
	}
}
