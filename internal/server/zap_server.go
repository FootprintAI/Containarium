package server

import (
	"context"
	"fmt"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	zapscanner "github.com/footprintai/containarium/internal/zap"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ZapServer implements the ZapService gRPC service
type ZapServer struct {
	pb.UnimplementedZapServiceServer
	store     *zapscanner.Store
	manager   *zapscanner.Manager
	installer *zapscanner.Installer
}

// NewZapServer creates a new ZAP server
func NewZapServer(store *zapscanner.Store, manager *zapscanner.Manager) *ZapServer {
	return &ZapServer{
		store:     store,
		manager:   manager,
		installer: zapscanner.NewInstaller(),
	}
}

// TriggerZapScan triggers an on-demand scan (non-blocking).
// Admin-only: ZAP scans are cluster-wide security operations that
// can target arbitrary containers; restricted to operators.
func (s *ZapServer) TriggerZapScan(ctx context.Context, req *pb.TriggerZapScanRequest) (*pb.TriggerZapScanResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if s.manager == nil {
		return nil, fmt.Errorf("ZAP scanner is not available")
	}

	scanRunID, err := s.manager.RunScan(ctx, "manual", req.ContainerName)
	if err != nil {
		return nil, fmt.Errorf("failed to trigger ZAP scan: %w", err)
	}

	msg := "ZAP scan enqueued — workers processing asynchronously"
	if req.ContainerName != "" {
		msg = fmt.Sprintf("ZAP scan enqueued (scope: %s) — workers processing asynchronously", req.ContainerName)
	}
	return &pb.TriggerZapScanResponse{
		ScanRunId: scanRunID,
		Message:   msg,
	}, nil
}

// ListZapScanRuns returns recent scan runs. Admin-only —
// security scan history can name arbitrary containers.
func (s *ZapServer) ListZapScanRuns(ctx context.Context, req *pb.ListZapScanRunsRequest) (*pb.ListZapScanRunsResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	runs, totalCount, err := s.store.ListScanRuns(ctx, int(req.Limit), int(req.Offset), req.ContainerName)
	if err != nil {
		return nil, fmt.Errorf("failed to list ZAP scan runs: %w", err)
	}

	var pbRuns []*pb.ZapScanRun
	for _, run := range runs {
		pbRun := zapScanRunToProto(&run)
		if run.Status == "running" {
			if count, err := s.store.CountFinishedJobs(ctx, run.ID); err == nil {
				pbRun.CompletedCount = int32(count)
			}
		} else {
			pbRun.CompletedCount = int32(run.TargetsCount)
		}
		pbRuns = append(pbRuns, pbRun)
	}

	return &pb.ListZapScanRunsResponse{
		ScanRuns:   pbRuns,
		TotalCount: totalCount,
	}, nil
}

// ListZapAlerts returns alerts with optional filtering.
// Admin-only — security alerts cross tenants.
func (s *ZapServer) ListZapAlerts(ctx context.Context, req *pb.ListZapAlertsRequest) (*pb.ListZapAlertsResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	params := zapscanner.AlertListParams{
		Risk:   req.Risk,
		Status: req.Status,
		Limit:  int(req.Limit),
		Offset: int(req.Offset),
	}

	alerts, totalCount, err := s.store.ListAlerts(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to list ZAP alerts: %w", err)
	}

	var pbAlerts []*pb.ZapAlert
	for _, a := range alerts {
		pbAlerts = append(pbAlerts, zapAlertToProto(&a))
	}

	return &pb.ListZapAlertsResponse{
		Alerts:     pbAlerts,
		TotalCount: totalCount,
	}, nil
}

// GetZapAlertSummary returns aggregate alert statistics.
// Admin-only — cluster-wide counts leak information about
// which tenants have unresolved findings.
func (s *ZapServer) GetZapAlertSummary(ctx context.Context, req *pb.GetZapAlertSummaryRequest) (*pb.GetZapAlertSummaryResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	summary, err := s.store.GetAlertSummary(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get ZAP alert summary: %w", err)
	}

	return &pb.GetZapAlertSummaryResponse{
		Summary: &pb.ZapAlertSummary{
			TotalAlerts:      summary.TotalAlerts,
			OpenAlerts:       summary.OpenAlerts,
			ResolvedAlerts:   summary.ResolvedAlerts,
			SuppressedAlerts: summary.SuppressedAlerts,
			HighCount:        summary.HighCount,
			MediumCount:      summary.MediumCount,
			LowCount:         summary.LowCount,
			InfoCount:        summary.InfoCount,
		},
	}, nil
}

// SuppressZapAlert suppresses an alert. Admin-only — alert
// suppression directly affects what an operator sees.
func (s *ZapServer) SuppressZapAlert(ctx context.Context, req *pb.SuppressZapAlertRequest) (*pb.SuppressZapAlertResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if err := s.store.SuppressAlert(ctx, req.AlertId, req.Reason); err != nil {
		return nil, fmt.Errorf("failed to suppress ZAP alert: %w", err)
	}

	return &pb.SuppressZapAlertResponse{
		Message: fmt.Sprintf("Alert %d suppressed", req.AlertId),
	}, nil
}

// GetZapConfig returns the current configuration.
//
// Intentionally not gated with RequireRole — exposes
// availability + interval, no tenant or finding data.
// Any authenticated user can call it to discover whether
// scanning is enabled.
func (s *ZapServer) GetZapConfig(ctx context.Context, req *pb.GetZapConfigRequest) (*pb.GetZapConfigResponse, error) {
	config := &pb.ZapConfig{
		Enabled: s.manager != nil,
	}

	if s.manager != nil {
		config.Interval = s.manager.Interval().String()
		config.ZapAvailable = s.manager.ZapAvailable()
		config.ZapVersion = s.manager.ZapVersion()
	}

	return &pb.GetZapConfigResponse{
		Config: config,
	}, nil
}

// GetZapReport downloads a scan report. Admin-only — reports
// can name arbitrary containers and disclose finding details.
func (s *ZapServer) GetZapReport(ctx context.Context, req *pb.GetZapReportRequest) (*pb.GetZapReportResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	// Serve pre-generated reports from the database (instant download)
	htmlReport, jsonReport, err := s.store.GetReport(ctx, req.ScanRunId)
	if err != nil {
		return nil, fmt.Errorf("scan run not found: %w", err)
	}

	format := req.Format
	if format == "" {
		format = "html"
	}

	var content, contentType, filename string

	switch format {
	case "html":
		content = htmlReport
		contentType = "text/html"
		filename = fmt.Sprintf("zap-report-%s.html", req.ScanRunId)
	case "json":
		content = jsonReport
		contentType = "application/json"
		filename = fmt.Sprintf("zap-report-%s.json", req.ScanRunId)
	default:
		return nil, fmt.Errorf("unsupported report format: %s (supported: html, json)", format)
	}

	if content == "" {
		return nil, fmt.Errorf("no %s report available for this scan run (report may not have been generated)", format)
	}

	return &pb.GetZapReportResponse{
		Content:     content,
		ContentType: contentType,
		Filename:    filename,
	}, nil
}

// InstallZap downloads and installs OWASP ZAP. Admin-only —
// installs a system tool on the daemon host.
func (s *ZapServer) InstallZap(ctx context.Context, req *pb.InstallZapRequest) (*pb.InstallZapResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if s.manager != nil && s.manager.ZapAvailable() {
		return &pb.InstallZapResponse{
			Success: true,
			Message: "ZAP is already installed and active",
		}, nil
	}

	if err := s.installer.InstallZap(); err != nil {
		return &pb.InstallZapResponse{
			Success: false,
			Message: fmt.Sprintf("installation failed: %v", err),
		}, nil
	}

	return &pb.InstallZapResponse{
		Success: true,
		Message: "OWASP ZAP installed successfully",
	}, nil
}

// zapScanRunToProto converts a store ScanRun to a proto ZapScanRun
func zapScanRunToProto(run *zapscanner.ScanRun) *pb.ZapScanRun {
	pbRun := &pb.ZapScanRun{
		Id:            run.ID,
		Trigger:       run.Trigger,
		Status:        run.Status,
		TargetsCount:  int32(run.TargetsCount),
		HighCount:     int32(run.HighCount),
		MediumCount:   int32(run.MediumCount),
		LowCount:      int32(run.LowCount),
		InfoCount:     int32(run.InfoCount),
		ErrorMessage:  run.ErrorMessage,
		StartedAt:     run.StartedAt.Format(time.RFC3339),
		ContainerName: run.ContainerName,
	}
	if run.CompletedAt != nil {
		pbRun.CompletedAt = run.CompletedAt.Format(time.RFC3339)
		pbRun.Duration = run.CompletedAt.Sub(run.StartedAt).Truncate(time.Second).String()
	}
	return pbRun
}

// zapAlertToProto converts a store AlertRecord to a proto ZapAlert
func zapAlertToProto(a *zapscanner.AlertRecord) *pb.ZapAlert {
	pbA := &pb.ZapAlert{
		Id:               a.ID,
		Fingerprint:      a.Fingerprint,
		PluginId:         a.PluginID,
		AlertName:        a.AlertName,
		Risk:             a.Risk,
		Confidence:       a.Confidence,
		Description:      a.Description,
		Url:              a.URL,
		Method:           a.Method,
		Evidence:         a.Evidence,
		Solution:         a.Solution,
		CweIds:           a.CWEIDs,
		References:       a.References,
		Status:           a.Status,
		FirstSeenAt:      a.FirstSeenAt.Format(time.RFC3339),
		LastSeenAt:       a.LastSeenAt.Format(time.RFC3339),
		Suppressed:       a.Suppressed,
		SuppressedReason: a.SuppressedReason,
	}
	if a.FirstScanRunID != nil {
		pbA.FirstScanRunId = *a.FirstScanRunID
	}
	if a.LastScanRunID != nil {
		pbA.LastScanRunId = *a.LastScanRunID
	}
	if a.ResolvedAt != nil {
		pbA.ResolvedAt = a.ResolvedAt.Format(time.RFC3339)
	}
	return pbA
}
