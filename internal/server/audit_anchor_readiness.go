package server

import (
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/policyreadiness"
)

// reportAuditAnchorReadiness sets the audit anchoring readiness entry (#3549):
// NOT_SERVING while the anchor sink refuses the chain, SERVING otherwise. The
// daemon reports SERVING at startup, so a daemon with audit logging off, or
// one whose anchor has not ticked yet, reads as anchoring rather than unknown.
func reportAuditAnchorReadiness(h *health.Server, st audit.AnchorState) {
	if h == nil {
		return
	}
	status := healthpb.HealthCheckResponse_SERVING
	if st.Refused {
		status = healthpb.HealthCheckResponse_NOT_SERVING
	}
	h.SetServingStatus(policyreadiness.AuditAnchorService, status)
}
