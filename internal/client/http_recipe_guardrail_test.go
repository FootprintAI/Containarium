package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestHTTPDeployRecipe_SendsGuardrailInput: the REST body carries
// guardrail_input in a form the grpc-gateway (protojson) decodes back to
// the same message, and an ungated deploy sends none.
func TestHTTPDeployRecipe_SendsGuardrailInput(t *testing.T) {
	var bodies []*pb.DeployRecipeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		req := &pb.DeployRecipeRequest{}
		if err := protojson.Unmarshal(b, req); err != nil {
			t.Errorf("body %s is not a DeployRecipeRequest: %v", b, err)
		}
		bodies = append(bodies, req)
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	in := &pb.GuardrailGateInput{
		StagingRef: "ds1",
		Attestation: &pb.GuardrailAttestation{
			SubjectSha256: "abc", PolicyHash: "def", KeyId: "k", Signature: []byte{1, 2, 3},
			Verdict:      pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS,
			KindsScanned: []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_PII},
		},
	}
	if _, err := c.DeployRecipe("gated", "alice", "", "", "", nil, in); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeployRecipe("plain", "alice", "", "", "", nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 {
		t.Fatalf("got %d requests", len(bodies))
	}
	if !proto.Equal(bodies[0].GetGuardrailInput(), in) || bodies[0].GetRecipeId() != "gated" {
		t.Fatalf("server decoded %v, want guardrail_input %v", bodies[0], in)
	}
	if bodies[1].GetGuardrailInput() != nil {
		t.Fatalf("ungated deploy sent guardrail_input %v", bodies[1].GetGuardrailInput())
	}
}
