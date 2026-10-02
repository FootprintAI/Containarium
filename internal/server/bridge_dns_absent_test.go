package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/bridgedns"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2232: an absent record is its own state with an opt-in hint, never
// DEGRADED; created/repaired and the creation time are surfaced.
func TestBridgeDNSStatusResponse_AbsentAndActions(t *testing.T) {
	now := time.Now()
	absent := bridgeDNSStatusResponse(bridgedns.Status{Bridge: "incusbr0", LastPass: now, Absent: true})
	if absent.State != pb.BridgeDNSState_BRIDGE_DNS_STATE_ABSENT || !strings.Contains(absent.Reason, "--bridge-dns-create") {
		t.Fatalf("absent → %v %q", absent.State, absent.Reason)
	}
	created := bridgeDNSStatusResponse(bridgedns.Status{Bridge: "incusbr0", LastPass: now, InSync: true, LastAction: bridgedns.ActionCreated, CreatedAt: now, LastApplied: now})
	if created.State != pb.BridgeDNSState_BRIDGE_DNS_STATE_IN_SYNC || created.LastAction != "created" || created.CreatedAt == nil {
		t.Fatalf("created → %v action=%q createdAt=%v", created.State, created.LastAction, created.CreatedAt)
	}
	repaired := bridgeDNSStatusResponse(bridgedns.Status{Bridge: "incusbr0", LastPass: now, InSync: true, LastAction: bridgedns.ActionRepaired, LastApplied: now})
	if repaired.LastAction != "repaired" || repaired.CreatedAt != nil {
		t.Fatalf("repaired → action=%q createdAt=%v", repaired.LastAction, repaired.CreatedAt)
	}
}

// The off switch is named in the NOT_MANAGED reason.
func TestGetBridgeDNSStatus_DisabledReason(t *testing.T) {
	srv := &ContainerServer{}
	srv.SetBridgeDNSDisabled(true)
	resp, err := srv.GetBridgeDNSStatus(testCtx(), &pb.GetBridgeDNSStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.State != pb.BridgeDNSState_BRIDGE_DNS_STATE_NOT_MANAGED || !strings.Contains(resp.Reason, "--bridge-dns-reconcile=false") {
		t.Fatalf("got %v %q", resp.State, resp.Reason)
	}
	srv.SetBridgeDNSDisabled(false)
	resp, _ = srv.GetBridgeDNSStatus(context.Background(), &pb.GetBridgeDNSStatusRequest{})
	_ = resp // unauthenticated path is covered elsewhere
}

// The construction gate honours the off switch and the opt-in.
func TestNewBridgeDNSReconciler_OffSwitchAndOptIn(t *testing.T) {
	be := &fakeBridgeDNSBackend{present: true, ip: "10.0.3.5"}
	base := &DualServerConfig{EnableAppHosting: true, BaseDomain: "example.com"}
	if r := newBridgeDNSReconciler(base, be, false); r == nil {
		t.Fatal("app hosting + base domain + core-caddy must build a reconciler")
	}
	off := *base
	off.BridgeDNSReconcileDisabled = true
	if r := newBridgeDNSReconciler(&off, be, true); r != nil {
		t.Fatal("--bridge-dns-reconcile=false must not build a reconciler, even on first install")
	}
}
