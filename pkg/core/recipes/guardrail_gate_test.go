package recipes

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func gatedYAML(gate string) string {
	return "recipes:\n  - id: gated\n    image: x\n    guardrail_gate:\n" + gate
}

// TestLoadGuardrailGate: a recipe's guardrail_gate reaches the proto as
// typed enums, and a gate the deploy could not honour is refused at load.
func TestLoadGuardrailGate(t *testing.T) {
	m := New()
	if err := m.LoadFromBytes([]byte(gatedYAML("      dataset_path: /data/train\n      require_kinds: [secret, pii]\n"))); err != nil {
		t.Fatalf("load: %v", err)
	}
	r, err := m.Get("gated")
	if err != nil {
		t.Fatal(err)
	}
	g := r.GetGuardrailGate()
	want := []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_SECRET, pb.GuardrailKind_GUARDRAIL_KIND_PII}
	if g.GetDatasetPath() != "/data/train" || len(g.GetRequireKinds()) != 2 || g.GetRequireKinds()[0] != want[0] || g.GetRequireKinds()[1] != want[1] {
		t.Fatalf("gate = %v, want /data/train with %v", g, want)
	}

	for name, gate := range map[string]string{
		"no dataset_path":       "      require_kinds: [pii]\n",
		"relative dataset_path": "      dataset_path: data\n",
		"root dataset_path":     "      dataset_path: /\n",
		"unclean dataset_path":  "      dataset_path: /data/../etc\n",
		"unknown kind":          "      dataset_path: /data\n      require_kinds: [email]\n",
	} {
		if err := New().LoadFromBytes([]byte(gatedYAML(gate))); err == nil || !strings.Contains(err.Error(), "guardrail_gate") {
			t.Errorf("%s: load = %v, want a guardrail_gate error", name, err)
		}
	}
}

// No built-in recipe is gated: gating one is a product decision, not a side
// effect of adding the field.
func TestEmbeddedCatalogHasNoGate(t *testing.T) {
	for _, r := range GetDefault().List() {
		if r.GetGuardrailGate() != nil {
			t.Errorf("built-in recipe %q has a guardrail_gate", r.GetId())
		}
	}
}
