package containariumotel

import (
	"testing"
)

func TestConfigFromEnv_Empty(t *testing.T) {
	clearEnv(t)
	cfg := ConfigFromEnv()
	if cfg.Endpoint != "" {
		t.Errorf("Endpoint = %q, want empty", cfg.Endpoint)
	}
	if cfg.ContainerID != "" {
		t.Errorf("ContainerID = %q, want empty", cfg.ContainerID)
	}
}

func TestConfigFromEnv_Populated(t *testing.T) {
	clearEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://10.0.3.42:4318")
	t.Setenv("OTEL_SERVICE_NAME", "payment-api")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "container.id=alice,backend.id=node-7")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Bearer abc")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	t.Setenv("CONTAINARIUM_CONTAINER_ID", "alice-container")
	t.Setenv("CONTAINARIUM_BACKEND_ID", "node-7")
	t.Setenv("CONTAINARIUM_TENANT_ID", "alice")
	t.Setenv("SERVICE_VERSION", "v1.2.3")

	cfg := ConfigFromEnv()
	if cfg.Endpoint != "http://10.0.3.42:4318" {
		t.Errorf("Endpoint = %q", cfg.Endpoint)
	}
	if cfg.ServiceName != "payment-api" {
		t.Errorf("ServiceName = %q", cfg.ServiceName)
	}
	if cfg.ContainerID != "alice-container" {
		t.Errorf("ContainerID = %q", cfg.ContainerID)
	}
	if cfg.BackendID != "node-7" {
		t.Errorf("BackendID = %q", cfg.BackendID)
	}
	if cfg.TenantID != "alice" {
		t.Errorf("TenantID = %q", cfg.TenantID)
	}
	if cfg.ServiceVersion != "v1.2.3" {
		t.Errorf("ServiceVersion = %q", cfg.ServiceVersion)
	}
	if cfg.Headers != "Authorization=Bearer abc" {
		t.Errorf("Headers = %q", cfg.Headers)
	}
}

// clearEnv unsets all distro-relevant env vars for the duration of t.
// t.Setenv handles cleanup; t.Helper signals this isn't a test step.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_SERVICE_NAME",
		"OTEL_RESOURCE_ATTRIBUTES",
		"OTEL_EXPORTER_OTLP_HEADERS",
		"OTEL_EXPORTER_OTLP_PROTOCOL",
		"CONTAINARIUM_CONTAINER_ID",
		"CONTAINARIUM_BACKEND_ID",
		"CONTAINARIUM_TENANT_ID",
		"SERVICE_VERSION",
	} {
		t.Setenv(k, "")
	}
}
