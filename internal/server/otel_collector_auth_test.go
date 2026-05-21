package server

import (
	"strings"
	"testing"
)

// Phase 2.5 follow-up — bearer enforcement in the generated
// collector config.

func TestBuildOTelCollectorConfig_NoBearerOmitsAuth(t *testing.T) {
	cfg := buildOTelCollectorConfig("10.0.3.99", nil, "")
	if strings.Contains(cfg, "bearertokenauth") {
		t.Fatalf("empty bearer should not emit bearertokenauth; got:\n%s", cfg)
	}
	if strings.Contains(cfg, "authenticator:") {
		t.Fatalf("empty bearer should not wire receiver auth; got:\n%s", cfg)
	}
	if !strings.Contains(cfg, "extensions: [health_check]") {
		t.Fatalf("extensions block should still list health_check; got:\n%s", cfg)
	}
}

func TestBuildOTelCollectorConfig_BearerEmitsExtension(t *testing.T) {
	cfg := buildOTelCollectorConfig("10.0.3.99", nil, "supersecret")
	checks := []string{
		`bearertokenauth:`,
		`scheme: "Bearer"`,
		`token: "supersecret"`,
		`authenticator: bearertokenauth`,
		`extensions: [bearertokenauth, health_check]`,
	}
	for _, s := range checks {
		if !strings.Contains(cfg, s) {
			t.Errorf("missing %q in:\n%s", s, cfg)
		}
	}
}

func TestBuildOTelCollectorConfig_BearerWiredOnBothProtocols(t *testing.T) {
	// The OTLP receiver has two protocol blocks (http, grpc).
	// Both must carry the auth.authenticator wiring or one
	// side stays open while the other enforces.
	cfg := buildOTelCollectorConfig("10.0.3.99", nil, "x")
	httpIdx := strings.Index(cfg, "http:")
	grpcIdx := strings.Index(cfg, "grpc:")
	if httpIdx < 0 || grpcIdx < 0 {
		t.Fatalf("config missing protocol blocks:\n%s", cfg)
	}
	// Count authenticator occurrences — should be 2 (one per protocol).
	if got := strings.Count(cfg, "authenticator: bearertokenauth"); got != 2 {
		t.Fatalf("expected 2 authenticator entries (http + grpc); got %d in:\n%s", got, cfg)
	}
}

func TestCollectorBearerForConfig_OffByDefault(t *testing.T) {
	resetBearerCache(t)
	t.Setenv("CONTAINARIUM_OTEL_REQUIRE_AUTH", "")
	if got := collectorBearerForConfig(); got != "" {
		t.Fatalf("default should be empty (enforcement off); got %q", got)
	}
}

func TestCollectorBearerForConfig_EnabledReturnsBearer(t *testing.T) {
	resetBearerCache(t)
	clearOTelEnv(t)
	t.Setenv(otelBearerEnvOverride, "test-bearer-value")
	t.Setenv("CONTAINARIUM_OTEL_REQUIRE_AUTH", "true")
	if got := collectorBearerForConfig(); got != "test-bearer-value" {
		t.Fatalf("enforcement on should return bearer; got %q", got)
	}
}

func TestCollectorBearerForConfig_UnrecognizedValueStaysOff(t *testing.T) {
	resetBearerCache(t)
	clearOTelEnv(t)
	t.Setenv(otelBearerEnvOverride, "test-bearer-value")
	t.Setenv("CONTAINARIUM_OTEL_REQUIRE_AUTH", "maybe")
	// A typo on the flag must NOT silently enable enforcement
	// when there's nothing to enforce against — but more
	// importantly, must not silently DISABLE it either when
	// the operator intended on. Fail-off is the safer default
	// here because partial enforcement (bearer present but
	// flag missing) just leaves the collector open, same as
	// pre-2.5; the alternative (fail-on with typo) would
	// silently drop every monitoring container.
	if got := collectorBearerForConfig(); got != "" {
		t.Fatalf("typo on flag should leave enforcement off; got %q", got)
	}
}
