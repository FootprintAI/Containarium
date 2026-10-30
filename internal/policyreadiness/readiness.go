// Package policyreadiness reports whether the daemon's policy stores are
// ready (#2483). A store is ready once its durable (Postgres) store is
// installed; until then its RPCs fail closed. Readiness is the standard
// grpc.health.v1 service, one status per policy service. The daemon's status
// probe reads it in-process; `containarium doctor` reads it through the REST
// gateway.
package policyreadiness

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// HTTPPath is where the REST gateway serves grpc.health.v1.Health/Check, with
// the service name in the `service` query parameter.
const HTTPPath = "/v1/health"

// CorePostgresService is the readiness entry for the daemon's startup
// Postgres check (#2824). NOT_SERVING means the check failed within its
// deadline, so the daemon is serving DEGRADED: every database-backed store
// was skipped at startup and stays off until the daemon restarts. A daemon
// with no Postgres configured does not report it.
const CorePostgresService = "containarium.core_postgres"

// Services returns the health service name of each policy store, in report
// order.
func Services() []string {
	return []string{
		pb.GuardrailPolicyService_ServiceDesc.ServiceName,
		pb.CodingToolEgressPolicyService_ServiceDesc.ServiceName,
		CorePostgresService,
	}
}

// displayNames are the operator-facing names doctor prints.
var displayNames = map[string]string{
	pb.GuardrailPolicyService_ServiceDesc.ServiceName:        "guardrail policy store",
	pb.CodingToolEgressPolicyService_ServiceDesc.ServiceName: "coding-tool egress policy store",
	CorePostgresService: "core Postgres (database-backed stores)",
}

// CheckFunc asks for one service's serving status. An error means the
// status could not be read at all (for example, the daemon is not running).
type CheckFunc func(ctx context.Context, service string) (healthpb.HealthCheckResponse_ServingStatus, error)

// Result is one policy store's readiness.
type Result struct {
	Service string
	Status  healthpb.HealthCheckResponse_ServingStatus
	// Err is set when the status could not be read.
	Err error
}

// Name is the store's operator-facing name.
func (r Result) Name() string {
	if n, ok := displayNames[r.Service]; ok {
		return n
	}
	return r.Service
}

// Ready reports whether the store is serving from its durable store.
func (r Result) Ready() bool {
	return r.Err == nil && r.Status == healthpb.HealthCheckResponse_SERVING
}

// Detail explains the result in one line.
func (r Result) Detail() string {
	switch {
	case r.Err != nil:
		return fmt.Sprintf("unknown (daemon not reachable: %v)", r.Err)
	case r.Status == healthpb.HealthCheckResponse_SERVING:
		return "ready"
	case r.Status == healthpb.HealthCheckResponse_NOT_SERVING && r.Service == CorePostgresService:
		return "unavailable (DEGRADED): the daemon's startup Postgres check failed, so database-backed stores were skipped; they stay off until the daemon restarts (CONTAINARIUM_RESTART_ON_POSTGRES_RECOVERY=1 restarts it once Postgres answers)"
	case r.Status == healthpb.HealthCheckResponse_NOT_SERVING:
		return "unavailable: Postgres is configured but the store is not installed; its APIs fail closed until the daemon's retry reaches the database"
	case r.Status == healthpb.HealthCheckResponse_SERVICE_UNKNOWN:
		return "unknown (this daemon does not report this store; it may predate readiness reporting)"
	default:
		return "unknown (status " + r.Status.String() + ")"
	}
}

// Run checks every policy store.
func Run(ctx context.Context, check CheckFunc) []Result {
	services := Services()
	out := make([]Result, 0, len(services))
	for _, svc := range services {
		st, err := check(ctx, svc)
		out = append(out, Result{Service: svc, Status: st, Err: err})
	}
	return out
}

// ServerCheck reads an in-process health server.
func ServerCheck(h *health.Server) CheckFunc {
	return func(ctx context.Context, service string) (healthpb.HealthCheckResponse_ServingStatus, error) {
		resp, err := h.Check(ctx, &healthpb.HealthCheckRequest{Service: service})
		if err != nil {
			// health.Server answers NotFound for a service it has no status for.
			return healthpb.HealthCheckResponse_SERVICE_UNKNOWN, nil
		}
		return resp.GetStatus(), nil
	}
}

// HTTPCheck reads the grpc-gateway health endpoint of the daemon at baseURL
// (for example http://localhost:8080). The gateway answers 200 with the
// HealthCheckResponse for SERVING, 503 for NOT_SERVING and 404 for a service
// it does not know.
func HTTPCheck(client *http.Client, baseURL string) CheckFunc {
	base := strings.TrimRight(baseURL, "/")
	return func(ctx context.Context, service string) (healthpb.HealthCheckResponse_ServingStatus, error) {
		u := base + HTTPPath + "?service=" + url.QueryEscape(service)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return healthpb.HealthCheckResponse_UNKNOWN, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return healthpb.HealthCheckResponse_UNKNOWN, err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if err != nil {
			return healthpb.HealthCheckResponse_UNKNOWN, err
		}
		switch resp.StatusCode {
		case http.StatusOK:
			var hc healthpb.HealthCheckResponse
			if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &hc); err != nil {
				return healthpb.HealthCheckResponse_UNKNOWN, fmt.Errorf("decode health response: %w", err)
			}
			return hc.GetStatus(), nil
		case http.StatusServiceUnavailable:
			return healthpb.HealthCheckResponse_NOT_SERVING, nil
		case http.StatusNotFound:
			return healthpb.HealthCheckResponse_SERVICE_UNKNOWN, nil
		default:
			return healthpb.HealthCheckResponse_UNKNOWN, fmt.Errorf("health endpoint answered HTTP %d", resp.StatusCode)
		}
	}
}
