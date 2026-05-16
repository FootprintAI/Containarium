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
	got := otelEnvVars(opts, "alice-container")
	if got == nil {
		t.Fatal("expected non-nil env vars when fully configured")
	}
	// Legacy OTEL_* form
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
	if !strings.Contains(attrs, "container.id=alice-container") {
		t.Errorf("OTEL_RESOURCE_ATTRIBUTES missing container.id: %q", attrs)
	}
	if !strings.Contains(attrs, "backend.id=fts-5900x-gpu") {
		t.Errorf("OTEL_RESOURCE_ATTRIBUTES missing backend.id: %q", attrs)
	}
	// New split form for sidecar compose-interpolation
	if got["CONTAINARIUM_CONTAINER_ID"] != "alice-container" {
		t.Errorf("CONTAINARIUM_CONTAINER_ID = %q, want %q", got["CONTAINARIUM_CONTAINER_ID"], "alice-container")
	}
	if got["CONTAINARIUM_BACKEND_ID"] != "fts-5900x-gpu" {
		t.Errorf("CONTAINARIUM_BACKEND_ID = %q, want %q", got["CONTAINARIUM_BACKEND_ID"], "fts-5900x-gpu")
	}
	if got["CONTAINARIUM_TENANT_ID"] != "alice" {
		t.Errorf("CONTAINARIUM_TENANT_ID = %q, want %q", got["CONTAINARIUM_TENANT_ID"], "alice")
	}
}

func TestOTelEnvVarsForMigration_EmptyEndpoint(t *testing.T) {
	if got := OTelEnvVarsForMigration("alice", "alice", "local", ""); got != nil {
		t.Fatalf("expected nil for empty endpoint, got %v", got)
	}
}

func TestOTelEnvVarsForMigration_Populated(t *testing.T) {
	got := OTelEnvVarsForMigration("alice", "alice-container", "fts-13700k-gpu", "http://10.0.0.2:4318")
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
	// Split form must match the legacy comma-encoded form
	if got["CONTAINARIUM_CONTAINER_ID"] != "alice-container" {
		t.Errorf("split CONTAINARIUM_CONTAINER_ID = %q, want alice-container", got["CONTAINARIUM_CONTAINER_ID"])
	}
	if got["CONTAINARIUM_BACKEND_ID"] != "fts-13700k-gpu" {
		t.Errorf("split CONTAINARIUM_BACKEND_ID = %q, want fts-13700k-gpu", got["CONTAINARIUM_BACKEND_ID"])
	}
	if got["CONTAINARIUM_TENANT_ID"] != "alice" {
		t.Errorf("split CONTAINARIUM_TENANT_ID = %q, want alice", got["CONTAINARIUM_TENANT_ID"])
	}
}
