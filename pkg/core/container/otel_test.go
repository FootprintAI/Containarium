package container

import (
	"strings"
	"testing"
)

func TestOtelEnvVars_MonitoringDisabled(t *testing.T) {
	opts := CreateOptions{
		Username:              "alice",
		Monitoring:            false,
		OTelCollectorEndpoint: "http://10.0.0.1:4318",
		BackendID:             "local",
	}
	if got := otelEnvVars(opts, "alice"); got != nil {
		t.Fatalf("expected nil when monitoring is off, got %v", got)
	}
}

func TestOtelEnvVars_MonitoringOnButNoEndpoint(t *testing.T) {
	opts := CreateOptions{
		Username:              "alice",
		Monitoring:            true,
		OTelCollectorEndpoint: "",
		BackendID:             "local",
	}
	if got := otelEnvVars(opts, "alice"); got != nil {
		t.Fatalf("expected nil when collector endpoint is empty, got %v", got)
	}
}

func TestOtelEnvVars_FullyConfigured(t *testing.T) {
	opts := CreateOptions{
		Username:              "alice",
		Monitoring:            true,
		OTelCollectorEndpoint: "http://10.0.0.1:4318",
		BackendID:             "fts-5900x-gpu",
	}
	got := otelEnvVars(opts, "alice")
	if got == nil {
		t.Fatal("expected non-nil env vars when fully configured")
	}
	if got["OTEL_EXPORTER_OTLP_ENDPOINT"] != "http://10.0.0.1:4318" {
		t.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT = %q, want %q", got["OTEL_EXPORTER_OTLP_ENDPOINT"], "http://10.0.0.1:4318")
	}
	if got["OTEL_EXPORTER_OTLP_PROTOCOL"] != "http/protobuf" {
		t.Errorf("OTEL_EXPORTER_OTLP_PROTOCOL = %q, want %q", got["OTEL_EXPORTER_OTLP_PROTOCOL"], "http/protobuf")
	}
	if got["OTEL_SERVICE_NAME"] != "alice" {
		t.Errorf("OTEL_SERVICE_NAME = %q, want %q", got["OTEL_SERVICE_NAME"], "alice")
	}
	attrs := got["OTEL_RESOURCE_ATTRIBUTES"]
	if !strings.Contains(attrs, "container.id=alice") {
		t.Errorf("OTEL_RESOURCE_ATTRIBUTES missing container.id: %q", attrs)
	}
	if !strings.Contains(attrs, "backend.id=fts-5900x-gpu") {
		t.Errorf("OTEL_RESOURCE_ATTRIBUTES missing backend.id: %q", attrs)
	}
}

func TestOTelEnvVarsForMigration_EmptyEndpoint(t *testing.T) {
	if got := OTelEnvVarsForMigration("alice", "alice", "local", ""); got != nil {
		t.Fatalf("expected nil for empty endpoint, got %v", got)
	}
}

func TestOTelEnvVarsForMigration_Populated(t *testing.T) {
	got := OTelEnvVarsForMigration("alice", "alice", "fts-13700k-gpu", "http://10.0.0.2:4318")
	if got == nil {
		t.Fatal("expected non-nil map")
	}
	if got["OTEL_EXPORTER_OTLP_ENDPOINT"] != "http://10.0.0.2:4318" {
		t.Errorf("endpoint mismatch: %q", got["OTEL_EXPORTER_OTLP_ENDPOINT"])
	}
	if got["OTEL_SERVICE_NAME"] != "alice" {
		t.Errorf("service name mismatch: %q", got["OTEL_SERVICE_NAME"])
	}
	attrs := got["OTEL_RESOURCE_ATTRIBUTES"]
	if !strings.Contains(attrs, "backend.id=fts-13700k-gpu") {
		t.Errorf("expected backend.id in attrs, got %q", attrs)
	}
}
