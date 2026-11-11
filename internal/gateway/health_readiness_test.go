package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/policyreadiness"
	"github.com/footprintai/containarium/pkg/version"
)

func TestHealthEndpoint_CorePostgresReadiness(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status healthpb.HealthCheckResponse_ServingStatus
		err    error
		want   healthStatus
	}{
		{"ready", healthpb.HealthCheckResponse_SERVING, nil, healthStatusHealthy},
		{"not configured", healthpb.HealthCheckResponse_SERVICE_UNKNOWN, nil, healthStatusHealthy},
		{"startup check failed", healthpb.HealthCheckResponse_NOT_SERVING, nil, healthStatusDegraded},
		{"unknown readiness", healthpb.HealthCheckResponse_UNKNOWN, nil, healthStatusDegraded},
		{"readiness error is private", healthpb.HealthCheckResponse_UNKNOWN, errors.New("postgres://example:private-password@db.example.test/state"), healthStatusDegraded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := func(_ context.Context, service string) (healthpb.HealthCheckResponse_ServingStatus, error) {
				if service != policyreadiness.CorePostgresService {
					t.Errorf("checked %q, want the core Postgres startup readiness", service)
				}
				return tc.status, tc.err
			}
			rec := httptest.NewRecorder()
			healthHandlerWithReadiness(check)(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("HTTP %d, want 200 so a degraded backend remains live", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			var got map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"status": string(tc.want), "version": version.GetVersion()}
			if tc.want == healthStatusDegraded {
				want["reason"] = "postgres unavailable"
			}
			if len(got) != len(want) {
				t.Errorf("health fields = %v, want only %v", got, want)
			}
			for key, value := range want {
				if got[key] != value {
					t.Errorf("%s = %q, want %q", key, got[key], value)
				}
			}
		})
	}
}

// Exercise the actual gateway mux on the early-bound port. Handing over
// the listener must not make a failed startup Postgres check look healthy.
func TestGatewayStart_KeepsPostgresDegradedAfterStartupHandover(t *testing.T) {
	sl := startStartupListener(t, "initialising daemon")
	base := "http://" + sl.Addr().String()
	h := health.NewServer()
	h.SetServingStatus(policyreadiness.CorePostgresService, healthpb.HealthCheckResponse_NOT_SERVING)

	tm, err := auth.NewTokenManager("test-secret-for-postgres-health-0123456789", "containarium")
	if err != nil {
		t.Fatal(err)
	}
	gs := NewGatewayServer("127.0.0.1:1", 1, auth.NewAuthMiddleware(tm), t.TempDir(), "", "")
	gs.SetStartupListener(sl)
	gs.SetReadinessCheck(policyreadiness.ServerCheck(h))

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- gs.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = sl.Close()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("gateway shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("gateway did not stop")
		}
	})

	deadline := time.Now().Add(3 * time.Second)
	for {
		code, got := getHealth(t, base)
		if code != http.StatusOK || got.Status != healthStatusDegraded {
			t.Fatalf("during startup handover: HTTP %d, status %q; want live but degraded", code, got.Status)
		}
		if got.Reason == "postgres unavailable" {
			break // The real gateway has taken over the listener.
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway did not take over: %v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Read the same readiness source on every request. In production the
	// failed startup entry stays NOT_SERVING until the daemon restarts.
	h.SetServingStatus(policyreadiness.CorePostgresService, healthpb.HealthCheckResponse_SERVING)
	if code, got := getHealth(t, base); code != http.StatusOK || got.Status != healthStatusHealthy || got.Reason != "" {
		t.Fatalf("after readiness becomes SERVING: HTTP %d, %v; want healthy without a reason", code, got)
	}
	h.SetServingStatus(policyreadiness.CorePostgresService, healthpb.HealthCheckResponse_NOT_SERVING)
	if code, got := getHealth(t, base); code != http.StatusOK || got.Status != healthStatusDegraded || got.Reason != "postgres unavailable" {
		t.Fatalf("after readiness becomes NOT_SERVING: HTTP %d, %v; want degraded", code, got)
	}
}
