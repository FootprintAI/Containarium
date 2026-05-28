package containariumotel

import "os"

// DistroConfig captures the env-driven knobs the distro cares about.
// It exists as a struct (not direct os.Getenv() calls scattered
// through the code) so tests can construct one directly without
// monkey-patching the process env, matching the Python distro's
// _config.py pattern.
type DistroConfig struct {
	// OTel-standard env vars. The SDK reads these directly too —
	// we capture them for diagnostics + branching on presence.
	Endpoint           string // OTEL_EXPORTER_OTLP_ENDPOINT
	ServiceName        string // OTEL_SERVICE_NAME
	ResourceAttributes string // OTEL_RESOURCE_ATTRIBUTES (raw, comma-joined)
	Headers            string // OTEL_EXPORTER_OTLP_HEADERS (raw, comma-joined)
	Protocol           string // OTEL_EXPORTER_OTLP_PROTOCOL

	// Containarium-stamped split-form identity (per OTEL-AGENT-RELAY-DESIGN
	// decision #5).
	ContainerID string // CONTAINARIUM_CONTAINER_ID
	BackendID   string // CONTAINARIUM_BACKEND_ID
	TenantID    string // CONTAINARIUM_TENANT_ID

	// Tenant-controlled, drives service.version stamping.
	ServiceVersion string // SERVICE_VERSION
}

// ConfigFromEnv reads the standard env vars into a DistroConfig.
func ConfigFromEnv() DistroConfig {
	return DistroConfig{
		Endpoint:           os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		ServiceName:        os.Getenv("OTEL_SERVICE_NAME"),
		ResourceAttributes: os.Getenv("OTEL_RESOURCE_ATTRIBUTES"),
		Headers:            os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"),
		Protocol:           os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"),
		ContainerID:        os.Getenv("CONTAINARIUM_CONTAINER_ID"),
		BackendID:          os.Getenv("CONTAINARIUM_BACKEND_ID"),
		TenantID:           os.Getenv("CONTAINARIUM_TENANT_ID"),
		ServiceVersion:     os.Getenv("SERVICE_VERSION"),
	}
}
