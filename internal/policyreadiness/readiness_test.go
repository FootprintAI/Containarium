package policyreadiness

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestServices_OnePerPolicyServicePlusCorePostgres(t *testing.T) {
	got := Services()
	want := []string{
		pb.GuardrailPolicyService_ServiceDesc.ServiceName,
		pb.CodingToolEgressPolicyService_ServiceDesc.ServiceName,
		CorePostgresService,
	}
	if len(got) != len(want) {
		t.Fatalf("Services() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Services()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRun_ReportsEachServiceAndClearsWhenServing(t *testing.T) {
	h := health.NewServer()
	for _, svc := range Services() {
		h.SetServingStatus(svc, healthpb.HealthCheckResponse_NOT_SERVING)
	}
	results := Run(context.Background(), ServerCheck(h))
	if len(results) != len(Services()) {
		t.Fatalf("Run returned %d results, want %d", len(results), len(Services()))
	}
	for _, r := range results {
		if r.Ready() {
			t.Errorf("%s: Ready() = true while NOT_SERVING", r.Service)
		}
		if !strings.Contains(r.Detail(), "unavailable") {
			t.Errorf("%s: Detail() = %q, want it to say unavailable", r.Service, r.Detail())
		}
	}

	for _, svc := range Services() {
		h.SetServingStatus(svc, healthpb.HealthCheckResponse_SERVING)
	}
	for _, r := range Run(context.Background(), ServerCheck(h)) {
		if !r.Ready() {
			t.Errorf("%s: Ready() = false once SERVING (detail %q)", r.Service, r.Detail())
		}
	}
}

func TestRun_UnreachableDaemonIsUnknownNotReady(t *testing.T) {
	results := Run(context.Background(), func(context.Context, string) (healthpb.HealthCheckResponse_ServingStatus, error) {
		return healthpb.HealthCheckResponse_UNKNOWN, errors.New("connection refused")
	})
	for _, r := range results {
		if r.Ready() {
			t.Errorf("%s: Ready() = true with the daemon unreachable", r.Service)
		}
		if !strings.Contains(r.Detail(), "unknown") {
			t.Errorf("%s: Detail() = %q, want it to say unknown", r.Service, r.Detail())
		}
	}
}

// HTTPCheck reads the grpc-gateway health endpoint: 200 with the
// HealthCheckResponse JSON, 503 for NOT_SERVING, 404 for an unknown service.
func TestHTTPCheck_MapsGatewayResponses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != HTTPPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("service") {
		case "serving":
			_, _ = w.Write([]byte(`{"status":"SERVING"}`))
		case "down":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"rpc error: code = Unavailable desc = status:NOT_SERVING","code":503}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found","code":404}`))
		}
	}))
	defer srv.Close()

	check := HTTPCheck(srv.Client(), srv.URL)
	cases := []struct {
		service string
		want    healthpb.HealthCheckResponse_ServingStatus
	}{
		{"serving", healthpb.HealthCheckResponse_SERVING},
		{"down", healthpb.HealthCheckResponse_NOT_SERVING},
		{"other", healthpb.HealthCheckResponse_SERVICE_UNKNOWN},
	}
	for _, c := range cases {
		got, err := check(context.Background(), c.service)
		if err != nil {
			t.Errorf("%s: err = %v", c.service, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: status = %v, want %v", c.service, got, c.want)
		}
	}

	srv.Close()
	if _, err := check(context.Background(), "serving"); err == nil {
		t.Error("closed daemon: want an error, got a status")
	}
}
