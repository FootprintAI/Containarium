package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// codeEgressHarness serves CodingToolEgressPolicyService (and, to prove the two
// stay apart, NetworkPolicyService) over in-process gRPC and through the
// generated grpc-gateway mux. Every call runs as an admin.
type codeEgressHarness struct {
	grpc pb.CodingToolEgressPolicyServiceClient
	np   pb.NetworkPolicyServiceClient
	mux  *runtime.ServeMux
}

func newCodeEgressHarness(t *testing.T) *codeEgressHarness {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		return h(auth.ContextWithTestSubject(ctx, "root-admin", auth.RoleAdmin), req)
	}))
	ce, _ := newTestCodeEgressServer()
	pb.RegisterCodingToolEgressPolicyServiceServer(srv, ce)
	pb.RegisterNetworkPolicyServiceServer(srv, NewNetworkPolicyServer(NewMemNetworkPolicyStore()))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
	}
	conn, err := grpc.NewClient("passthrough:///bufnet", opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	mux := runtime.NewServeMux()
	if err := pb.RegisterCodingToolEgressPolicyServiceHandler(context.Background(), mux, conn); err != nil {
		t.Fatal(err)
	}
	if err := pb.RegisterNetworkPolicyServiceHandler(context.Background(), mux, conn); err != nil {
		t.Fatal(err)
	}
	return &codeEgressHarness{grpc: pb.NewCodingToolEgressPolicyServiceClient(conn), np: pb.NewNetworkPolicyServiceClient(conn), mux: mux}
}

func (h *codeEgressHarness) rest(t *testing.T, method, path, body string, out proto.Message) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %s → %d: %s", method, path, rec.Code, b)
	}
	if out != nil {
		if err := protojson.Unmarshal(b, out); err != nil {
			t.Fatalf("decode %s %s: %v (%s)", method, path, err, b)
		}
	}
}

// TestCodeEgressPolicy_RESTAndGRPCAgree: a policy written over one transport
// reads back identically over the other, for a tenant and the cluster
// default, and a REST delete is visible over gRPC.
func TestCodeEgressPolicy_RESTAndGRPCAgree(t *testing.T) {
	h := newCodeEgressHarness(t)
	ctx := context.Background()

	// REST write (tenant in the path) → gRPC read.
	var put pb.SetCodingToolEgressPolicyResponse
	h.rest(t, http.MethodPut, "/v1/code/egress-policy/alice",
		`{"mode":"NETWORK_POLICY_MODE_ENFORCE","egressCidrs":["192.0.2.0/24"],"egressDomains":["api.example.com"]}`, &put)
	if put.GetPolicy().GetTenant() != "alice" {
		t.Fatalf("path tenant not applied: %+v", put.GetPolicy())
	}
	viaGRPC, err := h.grpc.GetCodingToolEgressPolicy(ctx, &pb.GetCodingToolEgressPolicyRequest{Tenant: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(viaGRPC.GetPolicy(), put.GetPolicy()) {
		t.Errorf("gRPC read %+v differs from REST write %+v", viaGRPC.GetPolicy(), put.GetPolicy())
	}
	var viaREST pb.GetCodingToolEgressPolicyResponse
	h.rest(t, http.MethodGet, "/v1/code/egress-policy/alice", "", &viaREST)
	if !proto.Equal(&viaREST, viaGRPC) {
		t.Errorf("REST and gRPC Get disagree:\nREST %+v\ngRPC %+v", &viaREST, viaGRPC)
	}

	// gRPC write of the cluster default → REST read on the tenant-less path.
	def, err := h.grpc.SetCodingToolEgressPolicy(ctx, &pb.SetCodingToolEgressPolicyRequest{Policy: &pb.CodingToolEgressPolicy{
		Mode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY, EgressDomains: []string{"default.example.com"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var defREST pb.GetCodingToolEgressPolicyResponse
	h.rest(t, http.MethodGet, "/v1/code/egress-policy", "", &defREST)
	if !proto.Equal(defREST.GetPolicy(), def.GetPolicy()) {
		t.Errorf("cluster default over REST %+v, over gRPC %+v", defREST.GetPolicy(), def.GetPolicy())
	}

	// REST delete → gRPC sees the tenant fall back to the default.
	h.rest(t, http.MethodDelete, "/v1/code/egress-policy/alice", "", nil)
	after, err := h.grpc.GetCodingToolEgressPolicy(ctx, &pb.GetCodingToolEgressPolicyRequest{Tenant: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if after.GetPolicy() != nil || after.GetEffective().GetSource() != pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_CLUSTER_DEFAULT {
		t.Errorf("after REST delete: %+v", after)
	}
}

// TestCodeEgressPolicy_LeavesNetworkPolicyUntouched: setting and deleting a
// tenant's coding-tool policy does not change that tenant's NetworkPolicy.
func TestCodeEgressPolicy_LeavesNetworkPolicyUntouched(t *testing.T) {
	h := newCodeEgressHarness(t)
	ctx := context.Background()
	np, err := h.np.SetNetworkPolicy(ctx, &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{
		Tenant: "alice", EgressCidrs: []string{"203.0.113.0/24"}, EgressDomains: []string{"pkg.example.com"},
		Mode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY,
	}})
	if err != nil {
		t.Fatal(err)
	}
	h.rest(t, http.MethodPut, "/v1/code/egress-policy/alice", `{"mode":"NETWORK_POLICY_MODE_ENFORCE"}`, nil)
	h.rest(t, http.MethodDelete, "/v1/code/egress-policy/alice", "", nil)

	got, err := h.np.GetNetworkPolicy(ctx, &pb.GetNetworkPolicyRequest{Tenant: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got.GetPolicy(), np.GetPolicy()) {
		t.Errorf("NetworkPolicy changed: before %+v, after %+v", np.GetPolicy(), got.GetPolicy())
	}
}
