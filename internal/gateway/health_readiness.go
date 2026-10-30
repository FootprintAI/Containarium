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

func healthHandlerWithReadiness(check policyreadiness.CheckFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if check == nil {
			healthHandler(w, r)
			return
		}
		st, err := check(r.Context(), policyreadiness.CorePostgresService)
		// No entry means Postgres is not configured. A failed startup entry
		// stays NOT_SERVING until restart, even if policy stores recover.
		if err == nil && (st == healthpb.HealthCheckResponse_SERVING || st == healthpb.HealthCheckResponse_SERVICE_UNKNOWN) {
			healthHandler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(healthResponse{
			Status:  healthStatusDegraded,
			Reason:  "postgres unavailable",
			Version: version.GetVersion(),
		})
	}
}
