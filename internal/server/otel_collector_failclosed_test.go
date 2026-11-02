package server

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/footprintai/containarium/internal/policyreadiness"
)

// #3443: CONTAINARIUM_OTEL_REQUIRE_AUTH=true with no usable bearer must fail
// closed: the collector is not started and the daemon reports it through the
// readiness (grpc.health.v1) surface.

// unavailableBearerEnv points the bearer source at a file that does not
// exist, so the bearer cannot be loaded.
func unavailableBearerEnv(t *testing.T) {
	t.Helper()
	resetBearerCache(t)
	clearOTelEnv(t)
	t.Setenv(otelBearerEnvFile, filepath.Join(t.TempDir(), "missing.bearer"))
}

func captureOTelLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func TestCollectorBearerForConfig_RequiredButUnavailableIsError(t *testing.T) {
	unavailableBearerEnv(t)
	t.Setenv("CONTAINARIUM_OTEL_REQUIRE_AUTH", "true")
	buf := captureOTelLog(t)
	got, err := collectorBearerForConfig()
	if !errors.Is(err, errOTelAuthBearerUnavailable) {
		t.Fatalf("want errOTelAuthBearerUnavailable, got bearer=%q err=%v", got, err)
	}
	if got != "" {
		t.Fatalf("no bearer expected, got %q", got)
	}
	if strings.Contains(buf.String(), "will NOT enforce auth") {
		t.Fatalf("must not log the fail-open message: %s", buf.String())
	}
}

func TestCollectorBearerForConfig_NotRequiredUnchangedWhenBearerUnavailable(t *testing.T) {
	for _, v := range []string{"", "false", "0", "maybe"} {
		unavailableBearerEnv(t)
		t.Setenv("CONTAINARIUM_OTEL_REQUIRE_AUTH", v)
		got, err := collectorBearerForConfig()
		if err != nil || got != "" {
			t.Fatalf("REQUIRE_AUTH=%q: want (\"\", nil), got (%q, %v)", v, got, err)
		}
	}
}

func TestEnsureOTelCollector_RequiredButNoBearerDoesNotStart(t *testing.T) {
	unavailableBearerEnv(t)
	t.Setenv("CONTAINARIUM_OTEL_REQUIRE_AUTH", "true")
	buf := captureOTelLog(t)
	// A zero CoreServices has no incus client: any attempt to create or
	// start the collector would panic, which is the failure we assert on.
	cs := &CoreServices{}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("collector start was attempted despite missing bearer: %v", r)
		}
	}()
	_, err := cs.EnsureOTelCollector(context.Background(), "10.0.0.9", nil)
	if !errors.Is(err, errOTelAuthBearerUnavailable) {
		t.Fatalf("want errOTelAuthBearerUnavailable, got %v", err)
	}
	if cs.GetOTelCollectorIP() != "" || cs.GetOTelCollectorEndpoint() != "" {
		t.Fatalf("collector must not be advertised")
	}
	if strings.Contains(buf.String(), "will NOT enforce auth") {
		t.Fatalf("must not log the fail-open message: %s", buf.String())
	}
}

func TestReportOTelCollectorReadiness(t *testing.T) {
	status := func(h *health.Server) healthpb.HealthCheckResponse_ServingStatus {
		r, err := h.Check(context.Background(), &healthpb.HealthCheckRequest{Service: policyreadiness.OTelCollectorAuthService})
		if err != nil {
			t.Fatalf("check: %v", err)
		}
		return r.GetStatus()
	}
	h := health.NewServer()
	reportOTelCollectorReadiness(h, nil)
	if got := status(h); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("nil error: want SERVING, got %v", got)
	}
	reportOTelCollectorReadiness(h, errOTelAuthBearerUnavailable)
	if got := status(h); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("bearer unavailable: want NOT_SERVING, got %v", got)
	}
	// An unrelated setup failure is not an auth refusal.
	h = health.NewServer()
	reportOTelCollectorReadiness(h, errors.New("incus down"))
	if got := status(h); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("unrelated error: want SERVING, got %v", got)
	}
}

func TestOTelCollectorAuthServiceListedAndExplained(t *testing.T) {
	found := false
	for _, s := range policyreadiness.Services() {
		if s == policyreadiness.OTelCollectorAuthService {
			found = true
		}
	}
	if !found {
		t.Fatal("readiness Services() must list the OTel collector auth entry")
	}
	d := policyreadiness.Result{Service: policyreadiness.OTelCollectorAuthService, Status: healthpb.HealthCheckResponse_NOT_SERVING}.Detail()
	if !strings.Contains(d, "CONTAINARIUM_OTEL_REQUIRE_AUTH") {
		t.Fatalf("detail should name the flag: %s", d)
	}
}
