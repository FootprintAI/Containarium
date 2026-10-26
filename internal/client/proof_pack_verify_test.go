package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3064 — both transports expose the same call.
var (
	_ interface {
		VerifyProofPack(context.Context, *pb.SealedProofPack) (*pb.VerifyProofPackResponse, error)
	} = (*HTTPClient)(nil)
	_ interface {
		VerifyProofPack(context.Context, *pb.SealedProofPack) (*pb.VerifyProofPackResponse, error)
	} = (*GRPCClient)(nil)
)

func TestHTTPClient_VerifyProofPack(t *testing.T) {
	var gotPath, gotAuth string
	var gotReq pb.VerifyProofPackRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		if err := protojson.Unmarshal(b, &gotReq); err != nil {
			t.Errorf("body is not protojson of the request: %v", err)
		}
		out, _ := protojson.Marshal(&pb.VerifyProofPackResponse{
			Verdict:       pb.ProofPackVerdict_PROOF_PACK_VERDICT_MISMATCH,
			FirstMismatch: &pb.ProofMismatch{StepIndex: 1, Name: "lint", Reason: "digest differs"},
		})
		_, _ = w.Write(out)
	}))
	defer srv.Close()
	c, _ := NewHTTPClient(srv.URL, "tok")
	sealed := &pb.SealedProofPack{Pack: &pb.ProofPack{Producer: "box"}, Seal: &pb.ProofPackSeal{AuditRowId: 7}}
	resp, err := c.VerifyProofPack(context.Background(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/proof-packs/verify" || gotAuth != "Bearer tok" || gotReq.Sealed.GetSeal().GetAuditRowId() != 7 {
		t.Errorf("request path=%q auth=%q req=%v", gotPath, gotAuth, &gotReq)
	}
	if resp.Ok || resp.FirstMismatch.GetName() != "lint" || resp.FirstMismatch.GetStepIndex() != 1 {
		t.Errorf("resp = %v", resp)
	}
}

func TestHTTPClient_VerifyProofPack_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"scope required: audit:read"}`))
	}))
	defer srv.Close()
	c, _ := NewHTTPClient(srv.URL, "t")
	_, err := c.VerifyProofPack(context.Background(), &pb.SealedProofPack{})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want it to carry HTTP 403", err)
	}
}
