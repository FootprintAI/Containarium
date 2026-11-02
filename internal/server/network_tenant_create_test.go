package server

import (
	"context"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"strings"
	"testing"
	"time"
)

func nativeAdmin() context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), "operator", []string{auth.RoleAdmin}, []string{auth.ScopeContainersRead, auth.ScopeContainersWrite})
}
func nativeUser() context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), "workload", []string{"user"}, []string{auth.ScopeContainersRead, auth.ScopeContainersWrite})
}

func TestNativeTenantAuthorizationAndPlacement(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		admin, local, tenancyOn bool
		req                     *pb.CreateContainerRequest
		want                    codes.Code
		key                     string
	}{
		{"admin explicit", true, true, false, &pb.CreateContainerRequest{NetworkTenant: "team-a"}, codes.OK, "team-a"},
		{"admin omitted", true, true, false, &pb.CreateContainerRequest{}, codes.OK, ""},
		{"user omitted legacy path when switch off", false, true, false, &pb.CreateContainerRequest{}, codes.OK, ""},
		{"user omitted reserved when switch on", false, true, true, &pb.CreateContainerRequest{}, codes.OK, "account:workload"},
		{"user omitted on non-local host legacy", false, false, true, &pb.CreateContainerRequest{}, codes.OK, ""},
		{"user shared forbidden", false, true, false, &pb.CreateContainerRequest{NetworkTenant: "team-a"}, codes.PermissionDenied, ""},
		{"user shared forbidden with switch on", false, true, true, &pb.CreateContainerRequest{NetworkTenant: "team-a"}, codes.PermissionDenied, ""},
		{"user explicit own forbidden", false, true, false, &pb.CreateContainerRequest{NetworkTenant: "account:workload"}, codes.PermissionDenied, ""},
		{"admin reserved forbidden", true, true, false, &pb.CreateContainerRequest{NetworkTenant: "account:workload"}, codes.InvalidArgument, ""},
		{"generic tenant label", true, true, false, &pb.CreateContainerRequest{Labels: map[string]string{"tenant": "team-a"}}, codes.InvalidArgument, ""},
		{"native label injection", false, true, false, &pb.CreateContainerRequest{Labels: map[string]string{incus.TenantLabelKey: "team-a"}}, codes.InvalidArgument, ""},
		{"cloud bypass", false, true, false, &pb.CreateContainerRequest{Labels: map[string]string{incus.CloudOrgIDLabel: "team-a"}}, codes.PermissionDenied, ""},
		{"conflicting cloud", true, true, false, &pb.CreateContainerRequest{NetworkTenant: "team-a", Labels: map[string]string{incus.CloudOrgIDLabel: "team-b"}}, codes.InvalidArgument, ""},
		{"non-admin pool refused while tenanted", false, false, true, &pb.CreateContainerRequest{Pool: "pool"}, codes.FailedPrecondition, ""},
		{"non-admin backend refused while tenanted", false, false, true, &pb.CreateContainerRequest{BackendId: "remote"}, codes.FailedPrecondition, ""},
		{"VM", true, true, false, &pb.CreateContainerRequest{NetworkTenant: "team-a", Isolation: pb.IsolationType_ISOLATION_TYPE_VM}, codes.InvalidArgument, ""},
		{"Windows", true, true, false, &pb.CreateContainerRequest{NetworkTenant: "team-a", OsType: pb.OSType_OS_TYPE_WINDOWS_2022}, codes.InvalidArgument, ""},
		{"K8s", true, false, false, &pb.CreateContainerRequest{NetworkTenant: "team-a"}, codes.FailedPrecondition, ""},
		{"remote", true, false, false, &pb.CreateContainerRequest{NetworkTenant: "team-a", BackendId: "remote"}, codes.FailedPrecondition, ""},
		{"pool", true, false, false, &pb.CreateContainerRequest{NetworkTenant: "team-a", Pool: "pool"}, codes.FailedPrecondition, ""},
		{"region accepted as no-op", true, true, false, &pb.CreateContainerRequest{NetworkTenant: "team-a", Region: "region"}, codes.OK, "team-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.req.Username = "workload"
			ctx := nativeUser()
			if tc.admin {
				ctx = nativeAdmin()
			}
			err := authorizeNetworkTenantCreate(ctx, tc.req, tc.local, tc.tenancyOn)
			if status.Code(err) != tc.want {
				t.Fatalf("code=%v wanted %v: %v", status.Code(err), tc.want, err)
			}
			if err == nil && tc.req.NetworkTenant != tc.key {
				t.Fatalf("key=%q", tc.req.NetworkTenant)
			}
		})
	}
	// A username matching an administrator domain still gets its own namespace.
	req := &pb.CreateContainerRequest{Username: "team-a"}
	if err := authorizeNetworkTenantCreate(nativeUser(), req, true, true); err != nil {
		t.Fatal(err)
	}
	if req.NetworkTenant != "account:team-a" {
		t.Fatal("username joined shared domain")
	}
	// Post-create Cloud attribution is not an alternate non-admin entry point.
	if err := authorizeNetworkTenantLabels(nativeUser(), map[string]string{incus.CloudOrgIDLabel: "team-a"}); status.Code(err) != codes.PermissionDenied {
		t.Fatal(err)
	}
}
func TestNativeTenantDryRunAndScopeFailBeforeProvisioning(t *testing.T) {
	s := &ContainerServer{manager: &container.Manager{}, nativeTenantReady: func() bool { return true }}
	req := &pb.CreateContainerRequest{Username: "workload", NetworkTenant: "team-a", DryRun: true}
	out, err := s.CreateContainer(nativeAdmin(), proto.Clone(req).(*pb.CreateContainerRequest))
	if err != nil || !out.GetDryRun() {
		t.Fatalf("preflight: %v", err)
	}
	omitted := &pb.CreateContainerRequest{Username: "workload", DryRun: true}
	for i := 0; i < 2; i++ {
		if _, err := s.CreateContainer(nativeUser(), omitted); err != nil {
			t.Fatal(err)
		}
	}
	if omitted.NetworkTenant != "" {
		t.Fatal("server mutated caller request during account normalization")
	}
	readOnly := auth.ContextWithTestSubjectScopes(context.Background(), "operator", []string{auth.RoleAdmin}, []string{auth.ScopeContainersRead})
	if _, err := s.CreateContainer(readOnly, req); status.Code(err) != codes.PermissionDenied {
		t.Fatal(err)
	}
	s.nativeTenantReady = func() bool { return false }
	if _, err := s.CreateContainer(nativeAdmin(), req); status.Code(err) != codes.FailedPrecondition {
		t.Fatal(err)
	}
	if _, err := s.CreateContainer(context.Background(), req); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
}
func TestNativeTenantCapabilityDoesNotAdvertisePolicyWrites(t *testing.T) {
	s := &NetworkServer{nativeTenantLocal: true, nativeTenantReady: func() bool { return true }}
	out, err := s.GetNetworkTenantCapabilities(nativeAdmin(), &pb.GetNetworkTenantCapabilitiesRequest{})
	if err != nil || !out.SharedTenantCreate || !out.NativeMembershipRead || out.AtomicTenantAccess || out.NetworkPolicyWrite || out.Contract != nativeTenantContract {
		t.Fatalf("bad capabilities %v %v", out, err)
	}
	if _, err := s.GetNetworkTenantCapabilities(nativeUser(), &pb.GetNetworkTenantCapabilitiesRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatal(err)
	}
	if _, err := s.GetNetworkTenantCapabilities(context.Background(), &pb.GetNetworkTenantCapabilitiesRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
	s.nativeTenantReady = nil
	out, _ = s.GetNetworkTenantCapabilities(nativeAdmin(), &pb.GetNetworkTenantCapabilitiesRequest{})
	if out.SharedTenantCreate || !strings.Contains(out.Reason, "Guard") {
		t.Fatal(out)
	}
}
func TestNativeTenantCapabilityFreshGuard(t *testing.T) {
	now := time.Now()
	g := &pb.GuardStatus{Mode: pb.GuardMode_GUARD_MODE_ENFORCE, FirewallDriver: "nftables", LastPass: now.UTC().Format(time.RFC3339), Entries: []*pb.GuardEntry{{Attached: true}}}
	if !nativeTenantGuardReady(g, now) {
		t.Fatal("fresh enforce rejected")
	}
	for _, mutate := range []func(*pb.GuardStatus){
		func(g *pb.GuardStatus) { g.Mode = pb.GuardMode_GUARD_MODE_OFF },
		func(g *pb.GuardStatus) { g.LastPass = now.Add(-4 * time.Minute).UTC().Format(time.RFC3339) },
		func(g *pb.GuardStatus) { g.LastPass = now.Add(time.Minute).UTC().Format(time.RFC3339) },
		func(g *pb.GuardStatus) { g.Unsupported = true },
		func(g *pb.GuardStatus) { g.Entries[0].Attached = false },
		func(g *pb.GuardStatus) { g.LastError = "failed" },
		func(g *pb.GuardStatus) { g.Unresolved = []string{"unknown"} },
	} {
		cp := proto.Clone(g).(*pb.GuardStatus)
		mutate(cp)
		if nativeTenantGuardReady(cp, now) {
			t.Fatalf("bad Guard accepted: %v", cp)
		}
	}
}
