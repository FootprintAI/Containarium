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
