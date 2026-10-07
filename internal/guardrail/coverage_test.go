package guardrail

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestKindsFor(t *testing.T) {
	both := []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_PII, pb.GuardrailKind_GUARDRAIL_KIND_SECRET}
	if got := KindsFor(DefaultPolicy()); !equalKinds(got, both) {
		t.Errorf("default policy must request both kinds, got %v", got)
	}
	// An empty policy is not "nothing": unlisted kinds default to REDACT.
	if got := KindsFor(&pb.GuardrailPolicy{}); !equalKinds(got, both) {
		t.Errorf("empty policy must still request both kinds, got %v", got)
	}
	// ALLOW drops a kind from the request; BLOCK keeps it (the engine must
	// still look, or BLOCK cannot fire).
	p := &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{
		{Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Action: pb.GuardrailAction_GUARDRAIL_ACTION_ALLOW},
		{Kind: pb.GuardrailKind_GUARDRAIL_KIND_PII, Action: pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK},
	}}
	if got := KindsFor(p); !equalKinds(got, []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_PII}) {
		t.Errorf("ALLOW secret / BLOCK pii -> [PII], got %v", got)
	}
	if len(KindsFor(DefaultPolicy())) == 0 {
		t.Fatal("KindsFor must never return an empty list — empty means 'whatever the engine has' (#2362)")
	}
}

func TestVerifyCoverage(t *testing.T) {
	att := &pb.GuardrailAttestation{KindsScanned: []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_PII}}
	if err := VerifyCoverage(att, nil); err != nil {
		t.Errorf("no requirement must pass: %v", err)
	}
	if err := VerifyCoverage(att, []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_PII}); err != nil {
		t.Errorf("PII covered must pass: %v", err)
	}
	err := VerifyCoverage(att, []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_PII, pb.GuardrailKind_GUARDRAIL_KIND_SECRET})
	if err == nil || !strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "PII") {
		t.Errorf("must name exactly the missing kind, got %v", err)
	}
	// An attestation from before kinds_scanned existed covers nothing it
	// can prove: any requirement fails.
	if err := VerifyCoverage(&pb.GuardrailAttestation{}, []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_PII}); err == nil {
		t.Error("legacy attestation with no kinds_scanned must fail a requirement")
	}
}

func equalKinds(a, b []pb.GuardrailKind) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
