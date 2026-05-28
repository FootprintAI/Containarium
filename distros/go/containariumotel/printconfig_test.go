package containariumotel

import (
	"strings"
	"testing"
)

func TestPrintConfig_Empty(t *testing.T) {
	var sb strings.Builder
	err := printConfig(&sb, DistroConfig{}, true)
	if err != nil {
		t.Fatalf("printConfig: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "TELEMETRY WILL BE NO-OP") {
		t.Errorf("missing no-op status; output:\n%s", out)
	}
	if !strings.Contains(out, "containarium.distro") {
		t.Errorf("missing distro stamp; output:\n%s", out)
	}
}

func TestPrintConfig_Populated(t *testing.T) {
	var sb strings.Builder
	err := printConfig(&sb, DistroConfig{
		Endpoint:       "http://10.0.3.42:4318",
		ServiceName:    "payment-api",
		ContainerID:    "alice-container",
		BackendID:      "node-7",
		TenantID:       "alice",
		ServiceVersion: "v1.2.3",
	}, true)
	if err != nil {
		t.Fatalf("printConfig: %v", err)
	}
	out := sb.String()
	for _, want := range []string{
		"10.0.3.42:4318",
		"payment-api",
		"alice-container",
		"node-7",
		"v1.2.3",
		"telemetry pipeline will be configured",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q; output:\n%s", want, out)
		}
	}
}

func TestPrintConfig_BearerRedactedByDefault(t *testing.T) {
	var sb strings.Builder
	err := printConfig(&sb, DistroConfig{
		Endpoint: "http://x:4318",
		Headers:  "Authorization=Bearer secret-token,X-Other=visible",
	}, true)
	if err != nil {
		t.Fatalf("printConfig: %v", err)
	}
	out := sb.String()
	if strings.Contains(out, "secret-token") {
		t.Errorf("bearer not redacted; output:\n%s", out)
	}
	if !strings.Contains(out, "<redacted>") {
		t.Errorf("missing <redacted> marker; output:\n%s", out)
	}
	if !strings.Contains(out, "X-Other=visible") {
		t.Errorf("non-secret header not preserved; output:\n%s", out)
	}
}

func TestPrintConfig_BearerVisibleWhenRedactOff(t *testing.T) {
	var sb strings.Builder
	err := printConfig(&sb, DistroConfig{
		Endpoint: "http://x:4318",
		Headers:  "Authorization=Bearer t",
	}, false)
	if err != nil {
		t.Fatalf("printConfig: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "Bearer t") {
		t.Errorf("bearer should be visible when redact off; output:\n%s", out)
	}
}
