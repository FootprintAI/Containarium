package server

import (
	"strings"
	"testing"
)

func TestMergeOTelDropLabels_DefaultsOnly(t *testing.T) {
	got := mergeOTelDropLabels(DefaultOTelDropLabels, nil)
	if len(got) != len(DefaultOTelDropLabels) {
		t.Fatalf("expected %d labels, got %d: %v", len(DefaultOTelDropLabels), len(got), got)
	}
	for _, want := range DefaultOTelDropLabels {
		found := false
		for _, g := range got {
			if g == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("default label %q missing from merge result %v", want, got)
		}
	}
}

func TestMergeOTelDropLabels_ExtrasUnioned(t *testing.T) {
	got := mergeOTelDropLabels(DefaultOTelDropLabels, []string{"tenant_email", "request_id"})
	// "request_id" is in defaults, should not duplicate; "tenant_email" should be added.
	seen := map[string]int{}
	for _, g := range got {
		seen[g]++
	}
	if seen["request_id"] != 1 {
		t.Errorf("request_id should appear exactly once, got %d", seen["request_id"])
	}
	if seen["tenant_email"] != 1 {
		t.Errorf("tenant_email should appear exactly once, got %d", seen["tenant_email"])
	}
}

func TestMergeOTelDropLabels_TrimsAndDropsEmpty(t *testing.T) {
	got := mergeOTelDropLabels(nil, []string{"  foo  ", "", "bar", " "})
	want := map[string]bool{"foo": true, "bar": true}
	if len(got) != len(want) {
		t.Fatalf("expected %d labels, got %d: %v", len(want), len(got), got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected label %q in result %v", g, got)
		}
	}
}

func TestBuildOTelCollectorConfig_IncludesExporter(t *testing.T) {
	cfg := buildOTelCollectorConfig("10.0.3.99", DefaultOTelDropLabels, "")
	if !strings.Contains(cfg, "http://10.0.3.99:8428/opentelemetry") {
		t.Errorf("config should target the supplied VM IP, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, "otlp:") {
		t.Errorf("config should declare otlp receiver")
	}
	if !strings.Contains(cfg, "health_check") {
		t.Errorf("config should declare health_check extension")
	}
}

func TestBuildOTelCollectorConfig_AntiSpoofingProcessor(t *testing.T) {
	cfg := buildOTelCollectorConfig("10.0.3.99", nil, "")
	// The attributes/identity processor must always be present —
	// it's the security boundary, not an optional add-on.
	if !strings.Contains(cfg, "attributes/identity") {
		t.Errorf("config must always include the anti-spoofing processor, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, "from_attribute: client.address") {
		t.Errorf("anti-spoofing processor must source from client.address, got:\n%s", cfg)
	}
}

func TestBuildOTelCollectorConfig_DropLabelsRendered(t *testing.T) {
	cfg := buildOTelCollectorConfig("10.0.3.99", []string{"request_id", "user_email"}, "")
	if !strings.Contains(cfg, "transform:") {
		t.Errorf("expected transform processor for non-empty drop list, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, `^request_id$|^user_email$`) {
		t.Errorf("drop regex not rendered correctly, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, "processors: [attributes/identity, transform, batch]") {
		t.Errorf("transform should appear in the metrics pipeline, got:\n%s", cfg)
	}
}

func TestBuildOTelCollectorConfig_NoDropLabelsSkipsTransform(t *testing.T) {
	cfg := buildOTelCollectorConfig("10.0.3.99", nil, "")
	if strings.Contains(cfg, "transform:") {
		t.Errorf("transform processor should be omitted when drop list is empty, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, "processors: [attributes/identity, batch]") {
		t.Errorf("pipeline should not reference transform when drop list is empty, got:\n%s", cfg)
	}
}

func TestRegexEscape_EscapesMetacharacters(t *testing.T) {
	cases := map[string]string{
		"plain":      "plain",
		"a.b":        `a\.b`,
		"a+b":        `a\+b`,
		"^anchor$":   `\^anchor\$`,
		"x[y]":       `x\[y\]`,
		"backslash\\": `backslash\\`,
	}
	for in, want := range cases {
		if got := regexEscape(in); got != want {
			t.Errorf("regexEscape(%q) = %q, want %q", in, got, want)
		}
	}
}
