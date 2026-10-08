package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	"github.com/footprintai/containarium/internal/server"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The guardrail policy contract over both transports (#2368): the REST
// PUT/GET /v1/guardrail/policy through the generated grpc-gateway shim and
// the gRPC calls reach the same real GuardrailPolicyServer and agree.

type guardrailPolicyClient interface {
	GetGuardrailPolicy() (*pb.GetGuardrailPolicyResponse, error)
	SetGuardrailPolicy(req *pb.SetGuardrailPolicyRequest) (*pb.SetGuardrailPolicyResponse, error)
}

func gpClaims(admin bool) *auth.Claims {
	if admin {
		return &auth.Claims{Username: "ops", Roles: []string{auth.RoleAdmin}}
	}
	return &auth.Claims{Username: "data-owner", Roles: []string{"user"}}
}

func startGRPCGuardrailPolicy(t *testing.T, srv *server.GuardrailPolicyServer, admin bool) *GRPCClient {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		return h(auth.ContextWithClaims(ctx, gpClaims(admin)), req)
	}))
	pb.RegisterGuardrailPolicyServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	c, err := NewGRPCClient(lis.Addr().String(), "", true)
	if err != nil {
		t.Fatalf("NewGRPCClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// startGatewayGuardrailPolicy mirrors the daemon gateway's JSON options and
// error body (internal/gateway/gateway.go), like startGatewayAgentServer.
func startGatewayGuardrailPolicy(t *testing.T, srv *server.GuardrailPolicyServer, admin bool) *HTTPClient {
	t.Helper()
	mux := runtime.NewServeMux(
		runtime.WithErrorHandler(func(_ context.Context, _ *runtime.ServeMux, _ runtime.Marshaler, w http.ResponseWriter, _ *http.Request, err error) {
			code := runtime.HTTPStatusFromCode(status.Code(err))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "code": code})
		}),
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			MarshalOptions:   protojson.MarshalOptions{EmitUnpopulated: true},
			UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: false},
		}),
	)
	if err := pb.RegisterGuardrailPolicyServiceHandlerServer(context.Background(), mux, srv); err != nil {
		t.Fatalf("register gateway handler: %v", err)
	}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(auth.ContextWithClaims(r.Context(), gpClaims(admin))))
	}))
	t.Cleanup(hs.Close)
	c, err := NewHTTPClient(hs.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	return c
}

// restSetStatus PUTs req to the gateway behind c and returns the HTTP status,
// so a refusal is asserted by its status rather than by error text.
func restSetStatus(t *testing.T, c *HTTPClient, req *pb.SetGuardrailPolicyRequest) int {
	t.Helper()
	body, err := protojson.Marshal(req)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	hreq, err := http.NewRequest(http.MethodPut, c.baseURL+"/v1/guardrail/policy", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		t.Fatalf("PUT /v1/guardrail/policy: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func gpTransportRequest(maxResidual int32) *pb.SetGuardrailPolicyRequest {
	seed := make([]byte, ed25519.SeedSize)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return &pb.SetGuardrailPolicyRequest{
		Policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{
			{Kind: pb.GuardrailKind_GUARDRAIL_KIND_PII, Action: pb.GuardrailAction_GUARDRAIL_ACTION_REDACT, MaxResidual: maxResidual},
			{Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Action: pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK},
		}},
		TrustedSigners: []*pb.GuardrailTrustedSigner{{KeyId: guardrail.KeyID(pub), PublicKey: pub, Label: "release key"}},
	}
}

// TestGuardrailPolicy_RESTAndGRPCAgree: a Set over one transport is read
// back identically over the other, both report not-configured the same way
// before any Set, and a refused call maps to the same status on both.
func TestGuardrailPolicy_RESTAndGRPCAgree(t *testing.T) {
	srv := server.NewGuardrailPolicyServer(guardrailpolicy.NewMemoryStore())
	clients := map[string]guardrailPolicyClient{
		"grpc": startGRPCGuardrailPolicy(t, srv, true),
		"rest": startGatewayGuardrailPolicy(t, srv, true),
	}

	for name, c := range clients {
		got, err := c.GetGuardrailPolicy()
		if err != nil || got.GetConfigured() {
			t.Fatalf("%s Get before any Set = (%v, %v), want configured=false", name, got, err)
		}
	}

	set, err := clients["rest"].SetGuardrailPolicy(gpTransportRequest(1))
	if err != nil {
		t.Fatalf("rest Set: %v", err)
	}
	if set.GetPolicy().GetRevision() != 1 || set.GetPolicy().GetUpdatedBy() != "ops" {
		t.Fatalf("rest Set = %v, want revision 1 by ops", set.GetPolicy())
	}
	viaGRPC, err := clients["grpc"].GetGuardrailPolicy()
	if err != nil {
		t.Fatalf("grpc Get: %v", err)
	}
	viaREST, err := clients["rest"].GetGuardrailPolicy()
	if err != nil {
		t.Fatalf("rest Get: %v", err)
	}
	if !proto.Equal(viaGRPC, viaREST) {
		t.Fatalf("transports disagree:\n grpc %v\n rest %v", viaGRPC, viaREST)
	}
	if !proto.Equal(viaREST.GetPolicy().GetTrustedSigners()[0], gpTransportRequest(1).GetTrustedSigners()[0]) {
		t.Fatalf("signer bytes did not survive the JSON round trip: %v", viaREST.GetPolicy().GetTrustedSigners())
	}

	if _, err := clients["grpc"].SetGuardrailPolicy(gpTransportRequest(2)); err != nil {
		t.Fatalf("grpc Set: %v", err)
	}
	viaREST, _ = clients["rest"].GetGuardrailPolicy()
	if viaREST.GetPolicy().GetRevision() != 2 || viaREST.GetPolicy().GetPolicy().GetRules()[0].GetMaxResidual() != 2 {
		t.Fatalf("rest Get after grpc Set = %v, want revision 2", viaREST.GetPolicy())
	}

	bad := gpTransportRequest(-1)
	if _, err := clients["grpc"].SetGuardrailPolicy(bad); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("grpc Set invalid = %v, want InvalidArgument", err)
	}
	if _, err := clients["rest"].SetGuardrailPolicy(bad); err == nil {
		t.Fatalf("rest Set invalid succeeded, want a refusal")
	}
	if got := restSetStatus(t, clients["rest"].(*HTTPClient), bad); got != http.StatusBadRequest {
		t.Fatalf("rest Set invalid = HTTP %d, want %d (InvalidArgument)", got, http.StatusBadRequest)
	}
	viaREST, _ = clients["rest"].GetGuardrailPolicy()
	if viaREST.GetPolicy().GetRevision() != 2 {
		t.Fatalf("revision after refused Sets = %d, want 2", viaREST.GetPolicy().GetRevision())
	}
}

// TestGuardrailPolicy_NonAdminSetRefusedOnBothTransports: AC3 over the wire.
func TestGuardrailPolicy_NonAdminSetRefusedOnBothTransports(t *testing.T) {
	srv := server.NewGuardrailPolicyServer(guardrailpolicy.NewMemoryStore())
	g := startGRPCGuardrailPolicy(t, srv, false)
	h := startGatewayGuardrailPolicy(t, srv, false)
	if _, err := g.SetGuardrailPolicy(gpTransportRequest(0)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("grpc non-admin Set = %v, want PermissionDenied", err)
	}
	if _, err := h.SetGuardrailPolicy(gpTransportRequest(0)); err == nil {
		t.Fatalf("rest non-admin Set succeeded, want a refusal")
	}
	if got := restSetStatus(t, h, gpTransportRequest(0)); got != http.StatusForbidden {
		t.Fatalf("rest non-admin Set = HTTP %d, want %d (PermissionDenied)", got, http.StatusForbidden)
	}
	if got, err := h.GetGuardrailPolicy(); err != nil || got.GetConfigured() {
		t.Fatalf("non-admin Get = (%v, %v), want readable and still not configured", got, err)
	}
}
