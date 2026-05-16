package cmd

import (
	"strings"
	"testing"
)

func TestRenderOTelComposeSnippet_AllFieldsRendered(t *testing.T) {
	got := renderOTelComposeSnippet(otelComposeInputs{
		ImageTag:          "v0.16.11",
		ServiceName:       "alice-otel",
		Username:          "alice",
		ContainerEnvName:  "alice-container",
		BackendEnvValue:   "containarium-jump-usw1",
		TenantEnvValue:    "alice",
		CollectorEnvValue: "http://10.0.3.112:4318",
	})

	mustContain := []string{
		// GHCR image tag (public package; tenants `docker pull` directly).
		"image: ghcr.io/footprintai/containarium-otel-sidecar:v0.16.11",
		// Service name composed from username
		"alice-otel:",
		// network_mode hint references the same service name
		`network_mode: "service:alice-otel"`,
		// All four ${VAR} interpolations present
		"${OTEL_EXPORTER_OTLP_ENDPOINT}",
		"${CONTAINARIUM_CONTAINER_ID}",
		"${CONTAINARIUM_BACKEND_ID}",
		"${CONTAINARIUM_TENANT_ID}",
		// All four current values shown as comments for verification
		"http://10.0.3.112:4318",
		"alice-container",
		"containarium-jump-usw1",
		// Health check block present
		"http://localhost:13133/",
		// SERVICE_VERSION with default fallback
		"${SERVICE_VERSION:-}",
	}
	for _, want := range mustContain {
		if !strings.Contains(got, want) {
			t.Errorf("compose snippet missing %q.\n--- snippet ---\n%s", want, got)
		}
	}
}

func TestRenderOTelComposeSnippet_DoesNotLeakHardcodedTenantInImage(t *testing.T) {
	// Different tenant — the image tag must NOT be tenant-derived.
	// (Tag tracks project version, not LXC.)
	got := renderOTelComposeSnippet(otelComposeInputs{
		ImageTag:          "v0.16.11",
		ServiceName:       "wordpress-otel",
		Username:          "wordpress",
		ContainerEnvName:  "wordpress-container",
		BackendEnvValue:   "containarium-jump-usw1",
		TenantEnvValue:    "wordpress",
		CollectorEnvValue: "http://10.0.3.112:4318",
	})
	if strings.Contains(got, "wordpress-otel-sidecar:") {
		// Catches a bug where the image name accidentally got the
		// service-name baked in.
		t.Errorf("image name should not include tenant; got snippet:\n%s", got)
	}
	if !strings.Contains(got, "image: ghcr.io/footprintai/containarium-otel-sidecar:v0.16.11") {
		t.Errorf("expected canonical GHCR image name, got:\n%s", got)
	}
}
