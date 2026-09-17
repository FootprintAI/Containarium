package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Phase 1.4 follow-up — handlers whose authz key is a
// container name. Each must:
//  1) reject a tenant who doesn't own the named container
//  2) reject a tenant when no name is given AND the empty-name
//     path would otherwise leak cross-tenant data
//  3) pass for the owning tenant (subject == owner)
//  4) pass for admin in both shapes
//
// As with the admin-only tests, the server is constructed
// with nil dependencies — a passing test means the gate
// fires before any nil-deref, i.e. structurally.

func tenantCtx(name string) context.Context {
	return auth.ContextWithTestSubject(context.Background(), name, "user")
}

func adminCtx() context.Context {
	return auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
}

// --- TrafficServer (4 RPCs) ---

func TestTrafficGetConnections_RejectsOtherTenant(t *testing.T) {
	srv := &TrafficServer{}
	_, err := srv.GetConnections(tenantCtx("alice"), &pb.GetConnectionsRequest{ContainerName: "bob-container"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestTrafficGetConnections_RejectsSystemContainerForTenant(t *testing.T) {
	srv := &TrafficServer{}
	_, err := srv.GetConnections(tenantCtx("alice"), &pb.GetConnectionsRequest{ContainerName: "caddy"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestTrafficGetConnectionSummary_RejectsOtherTenant(t *testing.T) {
	srv := &TrafficServer{}
	_, err := srv.GetConnectionSummary(tenantCtx("alice"), &pb.GetConnectionSummaryRequest{ContainerName: "bob-container"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestTrafficQueryHistory_RejectsOtherTenant(t *testing.T) {
	srv := &TrafficServer{}
	_, err := srv.QueryTrafficHistory(tenantCtx("alice"), &pb.QueryTrafficHistoryRequest{ContainerName: "bob-container"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestTrafficAggregates_RejectsOtherTenant(t *testing.T) {
	srv := &TrafficServer{}
	_, err := srv.GetTrafficAggregates(tenantCtx("alice"), &pb.GetTrafficAggregatesRequest{ContainerName: "bob-container"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

// --- SecurityServer ClamAV tenant reads ---

func TestListClamavReports_RejectsOtherTenant(t *testing.T) {
	srv := &SecurityServer{}
	_, err := srv.ListClamavReports(tenantCtx("alice"), &pb.ListClamavReportsRequest{ContainerName: "bob-container"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestListClamavReports_RejectsTenantBlankName(t *testing.T) {
	// Blank container_name = list across all containers; require admin.
	srv := &SecurityServer{}
	_, err := srv.ListClamavReports(tenantCtx("alice"), &pb.ListClamavReportsRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied (blank name on non-admin)", err)
	}
}

func TestTriggerClamavScan_RejectsOtherTenant(t *testing.T) {
	srv := &SecurityServer{}
	_, err := srv.TriggerClamavScan(tenantCtx("alice"), &pb.TriggerClamavScanRequest{ContainerName: "bob-container"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestTriggerClamavScan_RejectsTenantBlankName(t *testing.T) {
	// Blank container_name = scan all; require admin.
	srv := &SecurityServer{}
	_, err := srv.TriggerClamavScan(tenantCtx("alice"), &pb.TriggerClamavScanRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied (blank name on non-admin)", err)
	}
}

// --- Admin and owner pass the gate (both shapes) ---
//
// Each subtest wraps the call in recover() — the handler
// will nil-deref its store/collector AFTER the gate passes,
// which is exactly what we want to confirm: any panic that
// reaches us means the gate did NOT reject.

func mustPass(t *testing.T, label string, call func() error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			// Expected: panic on nil dep after gate passes.
			// Anything we observe here = gate let us through.
			return
		}
	}()
	err := call()
	if status.Code(err) == codes.PermissionDenied {
		t.Fatalf("%s: gate must NOT reject this caller; got %v", label, err)
	}
}

func TestTenantGates_AdminPasses_Blank(t *testing.T) {
	ctx := adminCtx()
	srv := &SecurityServer{}
	mustPass(t, "ListClamavReports blank", func() error {
		_, e := srv.ListClamavReports(ctx, &pb.ListClamavReportsRequest{})
		return e
	})
	mustPass(t, "TriggerClamavScan blank", func() error {
		_, e := srv.TriggerClamavScan(ctx, &pb.TriggerClamavScanRequest{})
		return e
	})
}

func TestTenantGates_AdminPasses_CrossTenant(t *testing.T) {
	ctx := adminCtx()
	srv := &TrafficServer{}
	mustPass(t, "GetConnections cross-tenant", func() error {
		_, e := srv.GetConnections(ctx, &pb.GetConnectionsRequest{ContainerName: "alice-container"})
		return e
	})
	mustPass(t, "GetTrafficAggregates cross-tenant", func() error {
		_, e := srv.GetTrafficAggregates(ctx, &pb.GetTrafficAggregatesRequest{ContainerName: "alice-container"})
		return e
	})
}

func TestTrafficGetConnections_OwnerPasses(t *testing.T) {
	srv := &TrafficServer{}
	mustPass(t, "owner GetConnections", func() error {
		_, e := srv.GetConnections(tenantCtx("alice"), &pb.GetConnectionsRequest{ContainerName: "alice-container"})
		return e
	})
}

func TestTriggerClamavScan_OwnerPasses(t *testing.T) {
	srv := &SecurityServer{}
	mustPass(t, "owner TriggerClamavScan", func() error {
		_, e := srv.TriggerClamavScan(tenantCtx("alice"), &pb.TriggerClamavScanRequest{ContainerName: "alice-container"})
		return e
	})
}

// --- NetworkServer egress-via-client (#808) — CWE-639 IDOR fix ---
//
// StartEgressProxy/StopEgressProxy previously called only
// auth.RequireScope(routes:write), an ordinary non-admin scope every
// tenant token carries — with no auth.AuthorizeContainerAccess check, any
// tenant could start/stop another tenant's egress relay by naming their
// container_name. tenantCtx below carries routes:write via ContextWithTestSubjectScopes so
// these tests fail closed on the SAME gate a real caller would hit, not
// merely on a missing scope.

func tenantCtxWithRoutesWrite(name string) context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), name, []string{"user"}, []string{auth.ScopeRoutesWrite})
}

func TestStartEgressProxy_RejectsOtherTenant(t *testing.T) {
	srv := &NetworkServer{}
	_, err := srv.StartEgressProxy(tenantCtxWithRoutesWrite("alice"), &pb.StartEgressProxyRequest{
		ContainerName: "bob-container",
		UpstreamPort:  18080,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestStopEgressProxy_RejectsOtherTenant(t *testing.T) {
	srv := &NetworkServer{}
	_, err := srv.StopEgressProxy(tenantCtxWithRoutesWrite("alice"), &pb.StopEgressProxyRequest{
		ContainerName: "bob-container",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestStartEgressProxy_RejectsOtherTenantBareUsername(t *testing.T) {
	// container_name may be passed without the "-container" suffix
	// (StartEgressProxy tolerates both forms) — the gate must normalize
	// before authorizing, not just when the suffix is already present.
	srv := &NetworkServer{}
	_, err := srv.StartEgressProxy(tenantCtxWithRoutesWrite("alice"), &pb.StartEgressProxyRequest{
		ContainerName: "bob",
		UpstreamPort:  18080,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestEgressProxy_OwnerPasses(t *testing.T) {
	srv := &NetworkServer{}
	ctx := tenantCtxWithRoutesWrite("alice")
	mustPass(t, "owner StartEgressProxy", func() error {
		_, e := srv.StartEgressProxy(ctx, &pb.StartEgressProxyRequest{ContainerName: "alice-container", UpstreamPort: 18080})
		return e
	})
	mustPass(t, "owner StopEgressProxy", func() error {
		_, e := srv.StopEgressProxy(ctx, &pb.StopEgressProxyRequest{ContainerName: "alice-container"})
		return e
	})
}

func TestEgressProxy_AdminPassesCrossTenant(t *testing.T) {
	srv := &NetworkServer{}
	ctx := auth.ContextWithTestSubjectScopes(context.Background(), "ops", []string{auth.RoleAdmin}, []string{auth.ScopeRoutesWrite})
	mustPass(t, "admin StartEgressProxy cross-tenant", func() error {
		_, e := srv.StartEgressProxy(ctx, &pb.StartEgressProxyRequest{ContainerName: "alice-container", UpstreamPort: 18080})
		return e
	})
	mustPass(t, "admin StopEgressProxy cross-tenant", func() error {
		_, e := srv.StopEgressProxy(ctx, &pb.StopEgressProxyRequest{ContainerName: "alice-container"})
		return e
	})
}
