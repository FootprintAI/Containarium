package recipes

import (
	"strings"
	"testing"
)

// TestLoadGuardrailGate_PresentButEmptyIsRefused: the presence of the
// guardrail_gate key is a gate declaration. An empty or null value must not
// load as an ungated recipe (fail-open); it is refused like {} is.
func TestLoadGuardrailGate_PresentButEmptyIsRefused(t *testing.T) {
	for name, gate := range map[string]string{
		"empty": "recipes:\n  - id: gated\n    image: x\n    guardrail_gate:\n",
		"null":  "recipes:\n  - id: gated\n    image: x\n    guardrail_gate: ~\n",
		"{}":    "recipes:\n  - id: gated\n    image: x\n    guardrail_gate: {}\n",
	} {
		err := New().LoadFromBytes([]byte(gate))
		if err == nil || !strings.Contains(err.Error(), "guardrail_gate") {
			t.Errorf("%s gate: load = %v, want a guardrail_gate error", name, err)
		}
	}
}

// TestLoadGuardrailGate_UnknownKeyIsRefused: a misspelt key under
// guardrail_gate must not load and silently drop what it meant (a typo of
// require_kinds would erase the recipe's own requirement).
func TestLoadGuardrailGate_UnknownKeyIsRefused(t *testing.T) {
	for name, tc := range map[string]struct{ body, key string }{
		"require_kinds typo": {"      dataset_path: /data\n      require_kind: [pii]\n", "require_kind"},
		"dataset_path typo":  {"      datasetpath: /data\n      dataset_path: /data\n", "datasetpath"},
		"unknown key":        {"      dataset_path: /data\n      read_only: true\n", "read_only"},
	} {
		err := New().LoadFromBytes([]byte(gatedYAML(tc.body)))
		if err == nil || !strings.Contains(err.Error(), `"gated"`) || !strings.Contains(err.Error(), tc.key) {
			t.Errorf("%s: load = %v, want an error naming the recipe and %q", name, err, tc.key)
		}
	}
	if err := New().LoadFromBytes([]byte(gatedYAML("      dataset_path: /data\n      require_kinds: [pii]\n"))); err != nil {
		t.Errorf("a valid gate no longer loads: %v", err)
	}
}
