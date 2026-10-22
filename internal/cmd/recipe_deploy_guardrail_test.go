package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestRecipeGuardrailInput: --guardrail-staging-ref and
// --guardrail-attestation build guardrail_input; neither means an ungated
// deploy; one without the other is refused before any request is sent.
func TestRecipeGuardrailInput(t *testing.T) {
	att := &pb.GuardrailAttestation{SubjectSha256: "abc", KeyId: "k", Verdict: pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS}
	b, err := protojson.Marshal(att)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "ds.attestation.json")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := recipeGuardrailInput("", "")
	if err != nil || got != nil {
		t.Fatalf("no flags = (%v, %v), want (nil, nil)", got, err)
	}
	got, err = recipeGuardrailInput("ds1", file)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetStagingRef() != "ds1" || !proto.Equal(got.GetAttestation(), att) {
		t.Fatalf("got %v, want staging_ref ds1 and the file's attestation", got)
	}
	for _, args := range [][2]string{{"ds1", ""}, {"", file}, {"ds1", file + ".missing"}} {
		if _, err := recipeGuardrailInput(args[0], args[1]); err == nil {
			t.Errorf("recipeGuardrailInput(%q, %q) = nil error, want refused", args[0], args[1])
		}
	}
}
