package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Phase 1.4 — second wave of admin-only gates. Each handler below
// is cluster-wide (no per-tenant scope) or operates on
// infrastructure that crosses tenants. Verify each one fires
// PermissionDenied for a non-admin subject *before* any field
// access — the gate must short-circuit even if downstream
// dependencies (stores, scanners) are nil.

func nonAdminCtx() context.Context {
	return auth.ContextWithTestSubject(context.Background(), "alice", "user")
}

// --- ZapServer ---

func TestZapTriggerScan_RejectsNonAdmin(t *testing.T) {
	srv := &ZapServer{}
	_, err := srv.TriggerZapScan(nonAdminCtx(), &pb.TriggerZapScanRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestZapListScanRuns_RejectsNonAdmin(t *testing.T) {
	srv := &ZapServer{}
	_, err := srv.ListZapScanRuns(nonAdminCtx(), &pb.ListZapScanRunsRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestZapListAlerts_RejectsNonAdmin(t *testing.T) {
	srv := &ZapServer{}
	_, err := srv.ListZapAlerts(nonAdminCtx(), &pb.ListZapAlertsRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestZapGetSummary_RejectsNonAdmin(t *testing.T) {
	srv := &ZapServer{}
	_, err := srv.GetZapAlertSummary(nonAdminCtx(), &pb.GetZapAlertSummaryRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestZapSuppressAlert_RejectsNonAdmin(t *testing.T) {
	srv := &ZapServer{}
	_, err := srv.SuppressZapAlert(nonAdminCtx(), &pb.SuppressZapAlertRequest{AlertId: 1})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestZapGetReport_RejectsNonAdmin(t *testing.T) {
	srv := &ZapServer{}
	_, err := srv.GetZapReport(nonAdminCtx(), &pb.GetZapReportRequest{ScanRunId: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestZapInstall_RejectsNonAdmin(t *testing.T) {
	srv := &ZapServer{}
	_, err := srv.InstallZap(nonAdminCtx(), &pb.InstallZapRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

// --- AlertServer (ContainerServer methods) ---

func TestCreateAlertRule_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	_, err := srv.CreateAlertRule(nonAdminCtx(), &pb.CreateAlertRuleRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestListAlertRules_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	_, err := srv.ListAlertRules(nonAdminCtx(), &pb.ListAlertRulesRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestGetAlertRule_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	_, err := srv.GetAlertRule(nonAdminCtx(), &pb.GetAlertRuleRequest{Id: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestUpdateAlertRule_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	_, err := srv.UpdateAlertRule(nonAdminCtx(), &pb.UpdateAlertRuleRequest{Id: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestDeleteAlertRule_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	_, err := srv.DeleteAlertRule(nonAdminCtx(), &pb.DeleteAlertRuleRequest{Id: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestUpdateAlertingConfig_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	_, err := srv.UpdateAlertingConfig(nonAdminCtx(), &pb.UpdateAlertingConfigRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestTestWebhook_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	_, err := srv.TestWebhook(nonAdminCtx(), &pb.TestWebhookRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestListWebhookDeliveries_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	_, err := srv.ListWebhookDeliveries(nonAdminCtx(), &pb.ListWebhookDeliveriesRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

// --- NetworkServer (admin-scope route + topology APIs) ---

func TestAddRoute_RejectsNonAdmin(t *testing.T) {
	srv := &NetworkServer{}
	_, err := srv.AddRoute(nonAdminCtx(), &pb.AddRouteRequest{Domain: "x", TargetIp: "1.2.3.4", TargetPort: 80})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

// TestAddRoute_RejectsScopeOnlyToken pins down the exact gap a code review
// caught on PR #1559: AddRoute requires RoleAdmin unconditionally, with no
// scope-based bypass, but every AgentSkill token is minted with scopes only
// and zero roles (RunAgentSkill, agent_server.go). A skill declaring
// routes:write can therefore never successfully call AddRoute — this test
// exercises the actual authorization path (not just scope-string presence
// on a manifest) so that gap can't silently reappear. It's why the
// deploy-branch skill (pkg/core/skills/skills.yaml) does not request
// routes:write and returns a private container address instead of calling
// AddRoute — see that skill's comment for the full rationale.
func TestAddRoute_RejectsScopeOnlyToken(t *testing.T) {
	srv := &NetworkServer{}
	// A skill-shaped token: no roles at all, but holds the exact scope AddRoute
	// checks first. If AddRoute ever grew a RequireRoleOrScope-style bypass for
	// routes:write, this would start passing the auth gate (and fail later, on
	// nil s.incusClient/store dependencies, not on PermissionDenied) — which is
	// the signal a future change actually closed this gap and this test (and
	// deploy-branch's scope list) should be revisited.
	ctx := auth.ContextWithTestSubjectScopes(context.Background(), "agent-deploy-branch", nil, []string{auth.ScopeRoutesWrite})
	_, err := srv.AddRoute(ctx, &pb.AddRouteRequest{Domain: "x", TargetIp: "1.2.3.4", TargetPort: 80})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied — a scope-only, zero-role token must not be able to call AddRoute", err)
	}
}

// TestCreateContainer_AllowsScopeOnlyToken is the positive-side companion to
// TestAddRoute_RejectsScopeOnlyToken: it proves a skill-shaped token (scopes
// only, zero roles) DOES clear CreateContainer's auth gate — confirming
// deploy-branch's actual design (provision + inspect a box, no route) is
// authorization-viable, unlike the original AddRoute-based design.
//
// Driven with IdleStopMinutes: -1, a request shape that trips
// CreateContainer's own early InvalidArgument validation
// (container_server.go) — a clean, backend-free error that proves auth AND
// request-validation were both reached, without going far enough to hit the
// real provisioning pipeline (which needs a live backend/key-provider this
// zero-value server doesn't have). The assertion is specifically that the
// failure is InvalidArgument, not PermissionDenied — i.e. auth was not the
// blocker.
//
// GetContainer is not exercised the same way here: unlike CreateContainer,
// it has no request-level validation to safely trip before reaching the box
// backend, and this test deliberately avoids reaching for a backend fake
// just to get a clean stopping point. Its auth gate is the identical
// two-line RequireScope(ctx, ScopeContainersRead)-only check, no
// RequireRole (container_server.go:1126-1129, read directly, not assumed).
func TestCreateContainer_AllowsScopeOnlyToken(t *testing.T) {
	ctx := auth.ContextWithTestSubjectScopes(context.Background(), "agent-deploy-branch", nil, []string{auth.ScopeContainersWrite, auth.ScopeContainersRead})

	srv := &ContainerServer{}
	_, err := srv.CreateContainer(ctx, &pb.CreateContainerRequest{Username: "agent-deploy-branch", IdleStopMinutes: -1})
	if status.Code(err) == codes.PermissionDenied {
		t.Fatalf("CreateContainer rejected a scope-only token on the auth check: %v", err)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected the IdleStopMinutes validation error (proving auth passed and validation was reached), got %v", err)
	}
}

func TestUpdateRoute_RejectsNonAdmin(t *testing.T) {
	srv := &NetworkServer{}
	_, err := srv.UpdateRoute(nonAdminCtx(), &pb.UpdateRouteRequest{Domain: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestDeleteRoute_RejectsNonAdmin(t *testing.T) {
	srv := &NetworkServer{}
	_, err := srv.DeleteRoute(nonAdminCtx(), &pb.DeleteRouteRequest{Domain: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestListPassthroughRoutes_RejectsNonAdmin(t *testing.T) {
	srv := &NetworkServer{}
	_, err := srv.ListPassthroughRoutes(nonAdminCtx(), &pb.ListPassthroughRoutesRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestAddPassthroughRoute_RejectsNonAdmin(t *testing.T) {
	srv := &NetworkServer{}
	_, err := srv.AddPassthroughRoute(nonAdminCtx(), &pb.AddPassthroughRouteRequest{ExternalPort: 80, TargetIp: "1.2.3.4", TargetPort: 80})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestDeletePassthroughRoute_RejectsNonAdmin(t *testing.T) {
	srv := &NetworkServer{}
	_, err := srv.DeletePassthroughRoute(nonAdminCtx(), &pb.DeletePassthroughRouteRequest{ExternalPort: 80})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestUpdatePassthroughRoute_RejectsNonAdmin(t *testing.T) {
	srv := &NetworkServer{}
	_, err := srv.UpdatePassthroughRoute(nonAdminCtx(), &pb.UpdatePassthroughRouteRequest{ExternalPort: 80})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestListDNSRecords_RejectsNonAdmin(t *testing.T) {
	srv := &NetworkServer{}
	_, err := srv.ListDNSRecords(nonAdminCtx(), &pb.ListDNSRecordsRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestGetNetworkTopology_RejectsNonAdmin(t *testing.T) {
	srv := &NetworkServer{}
	_, err := srv.GetNetworkTopology(nonAdminCtx(), &pb.GetNetworkTopologyRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

// --- PentestServer ---

func TestPentestTrigger_RejectsNonAdmin(t *testing.T) {
	srv := &PentestServer{}
	_, err := srv.TriggerPentestScan(nonAdminCtx(), &pb.TriggerPentestScanRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestPentestListRuns_RejectsNonAdmin(t *testing.T) {
	srv := &PentestServer{}
	_, err := srv.ListPentestScanRuns(nonAdminCtx(), &pb.ListPentestScanRunsRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestPentestGetRun_RejectsNonAdmin(t *testing.T) {
	srv := &PentestServer{}
	_, err := srv.GetPentestScanRun(nonAdminCtx(), &pb.GetPentestScanRunRequest{Id: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestPentestListFindings_RejectsNonAdmin(t *testing.T) {
	srv := &PentestServer{}
	_, err := srv.ListPentestFindings(nonAdminCtx(), &pb.ListPentestFindingsRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestPentestGetSummary_RejectsNonAdmin(t *testing.T) {
	srv := &PentestServer{}
	_, err := srv.GetPentestFindingSummary(nonAdminCtx(), &pb.GetPentestFindingSummaryRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestPentestSuppress_RejectsNonAdmin(t *testing.T) {
	srv := &PentestServer{}
	_, err := srv.SuppressPentestFinding(nonAdminCtx(), &pb.SuppressPentestFindingRequest{FindingId: 1})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestPentestInstall_RejectsNonAdmin(t *testing.T) {
	srv := &PentestServer{}
	_, err := srv.InstallPentestTool(nonAdminCtx(), &pb.InstallPentestToolRequest{ToolName: "nuclei"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestPentestRemediate_RejectsNonAdmin(t *testing.T) {
	srv := &PentestServer{}
	_, err := srv.RemediatePentestFinding(nonAdminCtx(), &pb.RemediatePentestFindingRequest{FindingId: 1})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

// --- SecurityServer (ClamAV) ---

func TestClamavSummary_RejectsNonAdmin(t *testing.T) {
	srv := &SecurityServer{}
	_, err := srv.GetClamavSummary(nonAdminCtx(), &pb.GetClamavSummaryRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestGetScanStatus_RejectsNonAdmin(t *testing.T) {
	srv := &SecurityServer{}
	_, err := srv.GetScanStatus(nonAdminCtx(), &pb.GetScanStatusRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

// --- Admin context passes the gate (smoke test) ---

func TestRBAC_AdminPassesGate(t *testing.T) {
	// Smoke test: an admin context must clear RequireRole. We
	// don't try to actually exercise the handler bodies (most
	// dereference nil stores). Just confirm the gate doesn't
	// fire — the call will fail downstream with a non-codes
	// error, but the status code must NOT be PermissionDenied.
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
	srv := &ZapServer{}
	_, err := srv.TriggerZapScan(ctx, &pb.TriggerZapScanRequest{})
	if status.Code(err) == codes.PermissionDenied {
		t.Fatalf("admin must pass the gate; got %v", err)
	}
}
