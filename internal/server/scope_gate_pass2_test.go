package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Phase 1.7b second pass — scope gates on the Zap, Pentest,
// SecurityServer ClamAV, AlertServer, and TrafficServer
// surfaces. Each test below names a token that has admin
// role + wrong scopes; the scope check must reject before
// the role check passes.
//
// Mirrors scope_gate_test.go's pattern: nil-dep server,
// gate must fire structurally (the body would nil-deref).

func adminWithScopes(scopes ...string) context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(),
		"ops", []string{auth.RoleAdmin}, scopes,
	)
}

// --- ZapServer (security:read/write) ---

func TestZap_RejectsWithoutSecurityScope(t *testing.T) {
	srv := &ZapServer{}
	ctxRead := adminWithScopes(auth.ScopeContainersRead) // wrong family
	cases := map[string]func() error{
		"TriggerZapScan": func() error {
			_, e := srv.TriggerZapScan(ctxRead, &pb.TriggerZapScanRequest{})
			return e
		},
		"ListZapScanRuns": func() error {
			_, e := srv.ListZapScanRuns(ctxRead, &pb.ListZapScanRunsRequest{})
			return e
		},
		"GetZapReport": func() error {
			_, e := srv.GetZapReport(ctxRead, &pb.GetZapReportRequest{ScanRunId: "x"})
			return e
		},
		"InstallZap": func() error {
			_, e := srv.InstallZap(ctxRead, &pb.InstallZapRequest{})
			return e
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			if err := call(); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("%s without security scope: got %v", name, err)
			}
		})
	}
}

// --- PentestServer ---

func TestPentest_RejectsWithoutSecurityScope(t *testing.T) {
	srv := &PentestServer{}
	ctx := adminWithScopes(auth.ScopeContainersRead)
	_, err := srv.TriggerPentestScan(ctx, &pb.TriggerPentestScanRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("TriggerPentestScan without security:write: got %v", err)
	}
	_, err = srv.ListPentestFindings(ctx, &pb.ListPentestFindingsRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ListPentestFindings without security:read: got %v", err)
	}
	_, err = srv.RemediatePentestFinding(ctx, &pb.RemediatePentestFindingRequest{FindingId: 1})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("RemediatePentestFinding without security:write: got %v", err)
	}
}

// --- SecurityServer (ClamAV) ---

func TestClamavSummary_RejectsWithoutSecurityRead(t *testing.T) {
	srv := &SecurityServer{}
	ctx := adminWithScopes(auth.ScopeContainersRead)
	_, err := srv.GetClamavSummary(ctx, &pb.GetClamavSummaryRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetClamavSummary without security:read: got %v", err)
	}
	_, err = srv.GetScanStatus(ctx, &pb.GetScanStatusRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetScanStatus without security:read: got %v", err)
	}
}

// --- AlertServer (alerts:read/write) ---

func TestAlerts_RejectsWithoutAlertsScope(t *testing.T) {
	srv := &ContainerServer{}
	ctx := adminWithScopes(auth.ScopeContainersRead) // wrong family
	_, err := srv.CreateAlertRule(ctx, &pb.CreateAlertRuleRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("CreateAlertRule without alerts:write: got %v", err)
	}
	_, err = srv.ListAlertRules(ctx, &pb.ListAlertRulesRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ListAlertRules without alerts:read: got %v", err)
	}
	_, err = srv.UpdateAlertingConfig(ctx, &pb.UpdateAlertingConfigRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("UpdateAlertingConfig without alerts:write: got %v", err)
	}
}

// --- TrafficServer (traffic:read) ---

func TestTraffic_RejectsWithoutTrafficRead(t *testing.T) {
	srv := &TrafficServer{}
	ctx := adminWithScopes(auth.ScopeContainersRead) // wrong family
	_, err := srv.GetConnections(ctx, &pb.GetConnectionsRequest{ContainerName: "alice-container"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetConnections without traffic:read: got %v", err)
	}
	_, err = srv.GetConnectionSummary(ctx, &pb.GetConnectionSummaryRequest{ContainerName: "alice-container"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetConnectionSummary without traffic:read: got %v", err)
	}
	_, err = srv.QueryTrafficHistory(ctx, &pb.QueryTrafficHistoryRequest{ContainerName: "alice-container"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("QueryTrafficHistory without traffic:read: got %v", err)
	}
	_, err = srv.GetTrafficAggregates(ctx, &pb.GetTrafficAggregatesRequest{ContainerName: "alice-container"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetTrafficAggregates without traffic:read: got %v", err)
	}
}

// --- Sanity: pre-1.7 tokens still pass ---

func TestPre17Tokens_PassPass2Handlers(t *testing.T) {
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
	mustPassScope(t, "ZapInstall (pre-1.7)", func() error {
		_, e := (&ZapServer{}).InstallZap(ctx, &pb.InstallZapRequest{})
		return e
	})
	mustPassScope(t, "CreateAlertRule (pre-1.7)", func() error {
		_, e := (&ContainerServer{}).CreateAlertRule(ctx, &pb.CreateAlertRuleRequest{})
		return e
	})
	mustPassScope(t, "TrafficGetConnections (pre-1.7)", func() error {
		_, e := (&TrafficServer{}).GetConnections(ctx, &pb.GetConnectionsRequest{ContainerName: "alice-container"})
		return e
	})
}
