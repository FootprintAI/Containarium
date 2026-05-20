package server

import (
	"strings"
	"testing"
)

// Phase 2.5 — OTel collector bind address is configurable via env
// var (audit C-HIGH-5). Default stays 0.0.0.0 for backwards compat;
// paranoid operators can pin to a specific bridge IP.

func TestOTelReceiverBindAddress_DefaultIsZero(t *testing.T) {
	t.Setenv("CONTAINARIUM_OTEL_COLLECTOR_BIND", "")
	if got := otelReceiverBindAddress(); got != "0.0.0.0" {
		t.Fatalf("default bind = %q, want 0.0.0.0", got)
	}
}

func TestOTelReceiverBindAddress_OverrideHonored(t *testing.T) {
	t.Setenv("CONTAINARIUM_OTEL_COLLECTOR_BIND", "10.0.3.5")
	if got := otelReceiverBindAddress(); got != "10.0.3.5" {
		t.Fatalf("bind = %q, want 10.0.3.5", got)
	}
}

func TestOTelReceiverBindAddress_TrimsWhitespace(t *testing.T) {
	t.Setenv("CONTAINARIUM_OTEL_COLLECTOR_BIND", "  127.0.0.1  ")
	if got := otelReceiverBindAddress(); got != "127.0.0.1" {
		t.Fatalf("bind = %q, want 127.0.0.1", got)
	}
}

func TestBuildOTelCollectorConfig_UsesOverrideBind(t *testing.T) {
	t.Setenv("CONTAINARIUM_OTEL_COLLECTOR_BIND", "10.0.3.5")
	cfg := buildOTelCollectorConfig("192.168.1.100", nil)

	// Both OTLP receivers should reflect the override.
	if !strings.Contains(cfg, "endpoint: 10.0.3.5:4318") {
		t.Fatalf("HTTP receiver bind not overridden:\n%s", cfg)
	}
	if !strings.Contains(cfg, "endpoint: 10.0.3.5:4317") {
		t.Fatalf("gRPC receiver bind not overridden:\n%s", cfg)
	}
	if strings.Contains(cfg, "endpoint: 0.0.0.0:") {
		t.Fatalf("override should replace 0.0.0.0 everywhere:\n%s", cfg)
	}
}

func TestBuildOTelCollectorConfig_DefaultBind(t *testing.T) {
	t.Setenv("CONTAINARIUM_OTEL_COLLECTOR_BIND", "")
	cfg := buildOTelCollectorConfig("192.168.1.100", nil)
	if !strings.Contains(cfg, "endpoint: 0.0.0.0:4318") {
		t.Fatalf("default HTTP bind missing:\n%s", cfg)
	}
	if !strings.Contains(cfg, "endpoint: 0.0.0.0:4317") {
		t.Fatalf("default gRPC bind missing:\n%s", cfg)
	}
}
