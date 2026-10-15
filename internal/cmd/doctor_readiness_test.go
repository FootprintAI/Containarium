//go:build !windows && !containarium_client

package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/footprintai/containarium/internal/policyreadiness"
)

// #2483: doctor prints policy-store readiness as an advisory section. It
// reports the unavailable state, clears once the stores are installed, and
// says "unknown" when the daemon cannot be reached.
func TestPrintDaemonReadiness_ReportsUnavailableAndClears(t *testing.T) {
	h := health.NewServer()
	for _, svc := range policyreadiness.Services() {
		h.SetServingStatus(svc, healthpb.HealthCheckResponse_NOT_SERVING)
	}
	var out bytes.Buffer
	printDaemonReadiness(&out, policyreadiness.Run(context.Background(), policyreadiness.ServerCheck(h)))
	got := out.String()
	for _, want := range []string{"advisory", "does not affect the exit code", "guardrail policy store", "coding-tool egress policy store", "unavailable"} {
		if !strings.Contains(got, want) {
			t.Errorf("section missing %q:\n%s", want, got)
		}
	}

	for _, svc := range policyreadiness.Services() {
		h.SetServingStatus(svc, healthpb.HealthCheckResponse_SERVING)
	}
	out.Reset()
	printDaemonReadiness(&out, policyreadiness.Run(context.Background(), policyreadiness.ServerCheck(h)))
	if got := out.String(); strings.Contains(got, "unavailable") || strings.Count(got, "ready") < 2 {
		t.Errorf("after recovery the section should report both stores ready:\n%s", got)
	}
}

func TestPrintDaemonReadiness_DaemonDownIsUnknown(t *testing.T) {
	var out bytes.Buffer
	printDaemonReadiness(&out, policyreadiness.Run(context.Background(), func(context.Context, string) (healthpb.HealthCheckResponse_ServingStatus, error) {
		return healthpb.HealthCheckResponse_UNKNOWN, errors.New("connection refused")
	}))
	if got := out.String(); !strings.Contains(got, "unknown") {
		t.Errorf("daemon down: want unknown, got:\n%s", got)
	}
}

func TestDoctor_HasDaemonURLFlag(t *testing.T) {
	f := doctorCmd.Flags().Lookup("daemon-url")
	if f == nil || f.DefValue != "http://localhost:8080" {
		t.Fatalf("--daemon-url flag = %+v, want default http://localhost:8080", f)
	}
}
