package gateway

import (
	"encoding/json"
	"net/http"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/footprintai/containarium/internal/policyreadiness"
	"github.com/footprintai/containarium/pkg/version"
)

// SetReadinessCheck supplies the daemon's in-process readiness source before
// Start. It must not perform network I/O: /health is a liveness endpoint.
func (gs *GatewayServer) SetReadinessCheck(check policyreadiness.CheckFunc) {
	gs.readinessCheck = check
}

// The fixed /health reasons the readiness source can set.
const (
	healthReasonPostgresUnavailable = "postgres unavailable"
	healthReasonAuditAnchorRefused  = "audit anchor refused"
)

func healthHandlerWithReadiness(check policyreadiness.CheckFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if check == nil {
			healthHandler(w, r)
			return
		}
		if reason := readinessDegradedReason(r, check); reason != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(healthResponse{
				Status:  healthStatusDegraded,
				Reason:  reason,
				Version: version.GetVersion(),
			})
			return
		}
		healthHandler(w, r)
	}
}

// readinessDegradedReason is the reason /health is degraded, or "" when it is
// healthy. Postgres first: with no database the audit chain cannot be read.
func readinessDegradedReason(r *http.Request, check policyreadiness.CheckFunc) string {
	st, err := check(r.Context(), policyreadiness.CorePostgresService)
	// No entry means Postgres is not configured. A failed startup entry
	// stays NOT_SERVING until restart, even if policy stores recover.
	if err != nil || (st != healthpb.HealthCheckResponse_SERVING && st != healthpb.HealthCheckResponse_SERVICE_UNKNOWN) {
		return healthReasonPostgresUnavailable
	}
	// #3549: anchoring refused on every tick. Only an explicit NOT_SERVING
	// counts: the daemon sets the entry itself, and a missing one is a daemon
	// that does not report it.
	if st, err := check(r.Context(), policyreadiness.AuditAnchorService); err == nil && st == healthpb.HealthCheckResponse_NOT_SERVING {
		return healthReasonAuditAnchorRefused
	}
	return ""
}
