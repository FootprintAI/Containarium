package server

import (
	"context"
	"testing"

	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/policyreadiness"
)

// #3549: the audit anchoring entry follows the anchor manager's state.
func TestReportAuditAnchorReadiness(t *testing.T) {
	status := func(h *health.Server) healthpb.HealthCheckResponse_ServingStatus {
		r, err := h.Check(context.Background(), &healthpb.HealthCheckRequest{Service: policyreadiness.AuditAnchorService})
		if err != nil {
			t.Fatalf("check: %v", err)
		}
		return r.GetStatus()
	}
	h := health.NewServer()
	reportAuditAnchorReadiness(h, audit.AnchorState{})
	if got := status(h); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("at startup: want SERVING, got %v", got)
	}
	reportAuditAnchorReadiness(h, audit.AnchorState{Refused: true, Checkpoint: 106, LastAnchored: 1036, Refusals: 1})
	if got := status(h); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("refused: want NOT_SERVING, got %v", got)
	}
	reportAuditAnchorReadiness(h, audit.AnchorState{Refusals: 1})
	if got := status(h); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("after a successful publish: want SERVING, got %v", got)
	}
	reportAuditAnchorReadiness(nil, audit.AnchorState{Refused: true}) // no readiness server: no panic
}
