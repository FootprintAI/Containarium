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
