package server

import (
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"testing"
	"time"
)

func TestTenantReviewLegacyCreateIgnoresUnavailableTenantDependencies(t *testing.T) {
	t.Setenv("CONTAINARIUM_NATIVE_ACCOUNT_TENANCY", "off")
	calls := 0
	s := &ContainerServer{manager: &container.Manager{}, nativeTenantReady: func() bool { calls++; return false }}
	req := &pb.CreateContainerRequest{Username: "workload", DryRun: true}
	out, err := s.CreateContainer(nativeUser(), req)
	if err != nil || !out.GetDryRun() || calls != 0 || req.NetworkTenant != "" {
		t.Fatalf("out=%v err=%v readinessCalls=%d requestTenant=%q", out, err, calls, req.NetworkTenant)
	}
}
func TestTenantReviewAccountNamespaceMustNotJoinSharedDomain(t *testing.T) {
	req := &pb.CreateContainerRequest{Username: "team-a"}
	if err := authorizeNetworkTenantCreate(nativeUser(), req, true, true); err != nil {
		t.Fatal(err)
	}
	actual := incus.ResolveTenant(req.NetworkTenant, "", "team-a-container")
	shared := incus.ResolveTenant("team-a", "", "admin-box-container")
	if actual == shared {
		t.Fatalf("account %q and admin shared tenant resolve to same Guard domain %q", req.NetworkTenant, actual)
	}
}
func TestTenantReviewLocalPlacementMustRemainSupported(t *testing.T) {
	s := &ContainerServer{peerPool: NewPeerPool("local-fixture", "", nil, "local-pool")}
	for _, req := range []*pb.CreateContainerRequest{{Username: "workload", BackendId: "local-fixture"}, {Username: "workload", BackendId: "local-fixture", Pool: "local-pool"}} {
		if req.Pool != "" {
			if err := s.resolvePoolPlacement(req); err != nil {
				t.Fatal(err)
			}
		}
		if s.createTargetsPeer(req) {
			t.Fatal("fixture unexpectedly targets peer")
		}
		if err := authorizeNetworkTenantCreate(nativeUser(), req, true, true); err != nil {
			t.Errorf("resolved local placement refused: %v", err)
		}
	}
}
func TestTenantReviewGuardCapabilityIndependentOfOtherBox(t *testing.T) {
	g := &pb.GuardStatus{Mode: pb.GuardMode_GUARD_MODE_ENFORCE, FirewallDriver: "nftables", LastPass: time.Now().UTC().Format(time.RFC3339), Entries: []*pb.GuardEntry{{Attached: false}}}
	if !nativeTenantGuardCapable(g, time.Now()) {
		t.Fatal("supported fresh Guard capability rejected solely for another unattached box")
	}
}

func TestTenantReviewResolvedLocalPlacementThroughCreate(t *testing.T) {
	t.Setenv("CONTAINARIUM_NATIVE_ACCOUNT_TENANCY", "on")
	s := &ContainerServer{manager: &container.Manager{}, nativeTenantReady: func() bool { return true }, peerPool: NewPeerPool("local-fixture", "", nil, "local-pool")}
	for _, req := range []*pb.CreateContainerRequest{{Username: "workload", BackendId: "local-fixture", DryRun: true}, {Username: "workload", BackendId: "local-fixture", Pool: "local-pool", DryRun: true}} {
		out, err := s.CreateContainer(nativeUser(), req)
		if err != nil || !out.GetDryRun() {
			t.Fatalf("local placement rejected: out=%v err=%v", out, err)
		}
	}
}

func TestTenantReviewGuardCapabilityStillRefusesUnavailableHost(t *testing.T) {
	now := time.Now()
	fresh := func() *pb.GuardStatus {
		return &pb.GuardStatus{Mode: pb.GuardMode_GUARD_MODE_ENFORCE, FirewallDriver: "nftables", LastPass: now.UTC().Format(time.RFC3339)}
	}
	for _, mutate := range []func(*pb.GuardStatus){
		func(g *pb.GuardStatus) { g.Mode = pb.GuardMode_GUARD_MODE_OFF },
		func(g *pb.GuardStatus) { g.Unsupported = true },
		func(g *pb.GuardStatus) { g.FirewallDriver = "xtables" },
		func(g *pb.GuardStatus) { g.StaleSince = now.UTC().Format(time.RFC3339) },
		func(g *pb.GuardStatus) { g.LastPass = now.Add(-4 * time.Minute).UTC().Format(time.RFC3339) },
		func(g *pb.GuardStatus) { g.LastPass = now.Add(time.Minute).UTC().Format(time.RFC3339) },
	} {
		g := fresh()
		mutate(g)
		if nativeTenantGuardCapable(g, now) {
			t.Fatalf("unavailable Guard advertised creation: %v", g)
		}
	}
}
