package server

import (
	"context"
	"errors"
	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"sync"
	"testing"
	"time"
)

func richAccessPolicy(key string) *pb.NetworkPolicy {
	return &pb.NetworkPolicy{Tenant: key, AllowIntraTenant: true, EgressCidrs: []string{"10.0.0.0/8"}, EgressDomains: []string{"example.com"}, Mode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, AllowMetadata: true, Source: "cloud-managed", EgressPreset: pb.EgressPreset_EGRESS_PRESET_ALLOW_LIST_ONLY, EgressMode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY, DenyRules: []*pb.NetworkPolicyDenyRule{{Cidr: "10.2.3.4/32", Port: 443, Note: "keep"}}}
}
func TestTenantAccessDirectionPreservationAndRevocation(t *testing.T) {
	store := NewMemNetworkPolicyStore()
	ctx := context.Background()
	old := richAccessPolicy("testing")
	_ = store.Set(ctx, old)
	// Set owns allow-policy, seed independently managed deny rules through its API.
	_, _ = store.MutateDenyRules(ctx, "testing", func([]*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error) { return old.DenyRules, nil })
	before, _ := store.Get(ctx, "testing")
	change := &pb.TenantAccessChange{Destination: "testing", AddSources: []string{"allinone"}, ExpectedRevision: PolicyRevision(before)}
	out, err := store.PatchTenantAccess(ctx, []*pb.TenantAccessChange{change})
	if err != nil {
		t.Fatal(err)
	}
	after := out[0].Policy
	if len(after.AllowFromTenants) != 1 || after.AllowFromTenants[0] != "allinone" {
		t.Fatal("authorization applied to wrong destination")
	}
	actual := proto.Clone(after).(*pb.NetworkPolicy)
	actual.AllowFromTenants = nil
	if !proto.Equal(actual, before) {
		t.Fatal("ingress patch clobbered another security field")
	}
	if _, err := store.Get(ctx, "allinone"); !errors.Is(err, ErrNetworkPolicyNotFound) {
		t.Fatal("one direction implicitly granted reverse access")
	}
	_, err = store.PatchTenantAccess(ctx, []*pb.TenantAccessChange{{Destination: "testing", RemoveSources: []string{"allinone"}, ExpectedRevision: PolicyRevision(after)}})
	if err != nil {
		t.Fatal(err)
	}
	restored, _ := store.Get(ctx, "testing")
	if !proto.Equal(restored, before) {
		t.Fatal("revoke failed to restore policy exactly")
	}
}
func TestTenantAccessBidirectionalAtomicConflict(t *testing.T) {
	store := NewMemNetworkPolicyStore()
	ctx := context.Background()
	_ = store.Set(ctx, &pb.NetworkPolicy{Tenant: "testing"})
	_, err := store.PatchTenantAccess(ctx, []*pb.TenantAccessChange{{Destination: "allinone", AddSources: []string{"testing"}, ExpectedRevision: "absent"}, {Destination: "testing", AddSources: []string{"allinone"}, ExpectedRevision: "absent"}})
	if !errors.Is(err, ErrTenantAccessConflict) {
		t.Fatalf("wanted revision conflict: %v", err)
	}
	if _, err = store.Get(ctx, "allinone"); !errors.Is(err, ErrNetworkPolicyNotFound) {
		t.Fatal("partial bidirectional write committed")
	}
	existing, _ := store.Get(ctx, "testing")
	out, err := store.PatchTenantAccess(ctx, []*pb.TenantAccessChange{{Destination: "allinone", AddSources: []string{"testing"}, ExpectedRevision: "absent"}, {Destination: "testing", AddSources: []string{"allinone"}, ExpectedRevision: PolicyRevision(existing)}})
	if err != nil || len(out) != 2 {
		t.Fatalf("bidirectional mutation: %v", err)
	}
}
func TestTenantAccessConcurrentPreviewHasOneWinner(t *testing.T) {
	store := NewMemNetworkPolicyStore()
	ctx := context.Background()
	_ = store.Set(ctx, &pb.NetworkPolicy{Tenant: "testing"})
	old, _ := store.Get(ctx, "testing")
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, src := range []string{"first", "second"} {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()
			_, err := store.PatchTenantAccess(ctx, []*pb.TenantAccessChange{{Destination: "testing", AddSources: []string{src}, ExpectedRevision: PolicyRevision(old)}})
			errs <- err
		}(src)
	}
	wg.Wait()
	close(errs)
	success, conflict := 0, 0
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, ErrTenantAccessConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("concurrent preview lost an update")
	}
}
func TestTenantAccessPermissionAndNoConnectivityClaim(t *testing.T) {
	s := newNPServer()
	s.tenantStoreDurable = func() bool { return true }
	s.tenantGuardRead = func() *pb.GuardStatus {
		return &pb.GuardStatus{Mode: pb.GuardMode_GUARD_MODE_ENFORCE, FirewallDriver: "nftables", LastPass: time.Now().UTC().Format(time.RFC3339)}
	}
	req := &pb.PatchTenantAccessRequest{Changes: []*pb.TenantAccessChange{{Destination: "testing", AddSources: []string{"allinone"}, ExpectedRevision: "absent"}}}
	for _, ctx := range []context.Context{context.Background(), auth.ContextWithTestSubject(context.Background(), "user", "user"), auth.ContextWithTestSubjectScopes(context.Background(), "admin", []string{auth.RoleAdmin}, []string{auth.ScopeContainersWrite})} {
		if _, err := s.PatchTenantAccess(ctx, req); err == nil {
			t.Fatal("unauthorized policy mutation")
		}
	}
	scoped := auth.ContextWithTestSubjectScopes(context.Background(), "admin", []string{auth.RoleAdmin}, []string{auth.ScopeContainersWrite})
	if _, err := s.SetNetworkPolicy(scoped, &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{Tenant: "testing", AllowFromTenants: []string{"allinone"}}}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("full-policy API bypassed ingress write scope")
	}
	result, err := s.PatchTenantAccess(npAdminCtx(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.ConnectivityTested || result.ApplicationState != pb.TenantAccessApplicationState_TENANT_ACCESS_APPLICATION_STATE_PENDING {
		t.Fatal("store success claimed network success")
	}
	req.Changes[0].ExpectedRevision = "absent"
	_, err = s.PatchTenantAccess(npAdminCtx(), req)
	if status.Code(err) != codes.Aborted {
		t.Fatalf("expected conflict: %v", err)
	}
}

func TestTenantAccessCapabilitySeparatesSupportPermissionAndGuard(t *testing.T) {
	s := newNPServer()
	s.tenantStoreDurable = func() bool { return true }
	s.tenantGuardRead = func() *pb.GuardStatus { return &pb.GuardStatus{Mode: pb.GuardMode_GUARD_MODE_OFF} }
	n := &NetworkServer{nativeTenantLocal: true, nativeTenantReady: func() bool { return false }, atomicTenantAccessReady: s.atomicTenantAccessAvailable}
	ctx := auth.ContextWithTestSubjectScopes(context.Background(), "operator", []string{auth.RoleAdmin}, []string{auth.ScopeContainersRead})
	caps, err := n.GetNetworkTenantCapabilities(ctx, &pb.GetNetworkTenantCapabilitiesRequest{})
	if err != nil || caps.SharedTenantCreate || !caps.AtomicTenantAccess || caps.NetworkPolicyWrite {
		t.Fatalf("independent feature/permission bits: %v %v", caps, err)
	}
	ctx = auth.ContextWithTestSubjectScopes(context.Background(), "operator", []string{auth.RoleAdmin}, []string{auth.ScopeContainersRead, auth.ScopeNetworkPolicyWrite})
	caps, err = n.GetNetworkTenantCapabilities(ctx, &pb.GetNetworkTenantCapabilitiesRequest{})
	if err != nil || !caps.NetworkPolicyWrite {
		t.Fatal(caps, err)
	}
	req := &pb.PatchTenantAccessRequest{Changes: []*pb.TenantAccessChange{{Destination: "team-b", AddSources: []string{"team-a"}, ExpectedRevision: "absent"}}}
	if _, err := s.PatchTenantAccess(ctx, req); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("grant accepted with Guard off", err)
	}
	existing := &pb.NetworkPolicy{Tenant: "team-b", AllowFromTenants: []string{"team-a"}}
	if err := s.store.Set(ctx, existing); err != nil {
		t.Fatal(err)
	}
	req.Changes[0] = &pb.TenantAccessChange{Destination: "team-b", RemoveSources: []string{"team-a"}, ExpectedRevision: PolicyRevision(existing)}
	result, err := s.PatchTenantAccess(ctx, req)
	if err != nil || result.ApplicationState != pb.TenantAccessApplicationState_TENANT_ACCESS_APPLICATION_STATE_PENDING || len(result.Policies[0].Policy.AllowFromTenants) != 0 {
		t.Fatalf("safe revoke not recorded: %v %v", result, err)
	}
}

func TestTenantAccessAbsentRevokeDoesNotCreateDefaultPolicy(t *testing.T) {
	store := NewMemNetworkPolicyStore()
	_, err := store.PatchTenantAccess(context.Background(), []*pb.TenantAccessChange{{Destination: "team-b", RemoveSources: []string{"team-a"}, ExpectedRevision: "absent"}})
	if err == nil {
		t.Fatal("revoke of absent policy created a default record")
	}
	if _, err := store.Get(context.Background(), "team-b"); !errors.Is(err, ErrNetworkPolicyNotFound) {
		t.Fatal(err)
	}
}
