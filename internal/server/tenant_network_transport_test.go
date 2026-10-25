package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/mcp"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func tenantTransportServer() *NetworkPolicyServer {
	s := NewNetworkPolicyServer(NewMemNetworkPolicyStore())
	s.tenantStoreDurable = func() bool { return true }
	s.tenantGuardRead = func() *pb.GuardStatus {
		return &pb.GuardStatus{Mode: pb.GuardMode_GUARD_MODE_ENFORCE, FirewallDriver: "nftables", LastPass: time.Now().UTC().Format(time.RFC3339)}
	}
	return s
}
func transportCtx(ctx context.Context) context.Context {
	return auth.ContextWithTestSubjectScopes(ctx, "fixture-admin", []string{auth.RoleAdmin}, []string{auth.ScopeContainersRead, auth.ScopeNetworkPolicyRead, auth.ScopeNetworkPolicyWrite})
}
func TestTenantAccessRESTAndGRPCHaveSameContract(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		return next(transportCtx(ctx), req)
	}))
	pb.RegisterNetworkPolicyServiceServer(srv, tenantTransportServer())
	go func() { _ = srv.Serve(listener) }()
	defer srv.Stop()
	conn, err := grpc.NewClient("passthrough:///fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	gateway := runtime.NewServeMux()
	if err := pb.RegisterNetworkPolicyServiceHandler(context.Background(), gateway, conn); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/v1/network-policies/tenant-access", strings.NewReader(`{"changes":[{"destination":"testing","addSources":["allinone"],"expectedRevision":"absent"}]}`))
	request.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	gateway.ServeHTTP(out, request)
	if out.Code != 200 {
		t.Fatalf("REST patch: %d %s", out.Code, out.Body.String())
	}
	observed, err := pb.NewNetworkPolicyServiceClient(conn).GetNetworkPolicy(context.Background(), &pb.GetNetworkPolicyRequest{Tenant: "testing"})
	if err != nil {
		t.Fatal(err)
	}
	if len(observed.Policy.AllowFromTenants) != 1 || observed.Policy.AllowFromTenants[0] != "allinone" || len(observed.Revision) != 64 {
		t.Fatal("gRPC read did not observe REST patch")
	}
	_, err = pb.NewNetworkPolicyServiceClient(conn).PatchTenantAccess(context.Background(), &pb.PatchTenantAccessRequest{Changes: []*pb.TenantAccessChange{{Destination: "testing", RemoveSources: []string{"allinone"}, ExpectedRevision: observed.Revision}}})
	if err != nil {
		t.Fatal(err)
	}
	got := httptest.NewRecorder()
	gateway.ServeHTTP(got, httptest.NewRequest("GET", "/v1/network-policies/testing", nil))
	var value pb.GetNetworkPolicyResponse
	if err := protojson.Unmarshal(got.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if len(value.Policy.AllowFromTenants) != 0 {
		t.Fatal("REST did not observe gRPC revoke")
	}
}
func TestTenantAccessMCPInitializeListAndActualCall(t *testing.T) {
	s := tenantTransportServer()
	mux := runtime.NewServeMux(runtime.WithMetadata(func(ctx context.Context, _ *http.Request) metadata.MD {
		md, _ := metadata.FromIncomingContext(transportCtx(ctx))
		return md
	}))
	if err := pb.RegisterNetworkPolicyServiceHandlerServer(context.Background(), mux, s); err != nil {
		t.Fatal(err)
	}
	net := &NetworkServer{nativeTenantLocal: true, nativeTenantReady: func() bool { return true }, atomicTenantAccessReady: s.atomicTenantAccessAvailable}
	if err := pb.RegisterNetworkServiceHandlerServer(context.Background(), mux, net); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(mux)
	defer server.Close()
	requests := []map[string]any{
		{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "isolated-tenant-test", "version": "1"}}},
		{"jsonrpc": "2.0", "method": "notifications/initialized"},
		{"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
		{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{"name": "network_tenant_capabilities", "arguments": map[string]any{}}},
		{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]any{"name": "patch_tenant_access", "arguments": map[string]any{"changes": []any{map[string]any{"destination": "testing", "add_sources": []string{"allinone"}, "expected_revision": "absent"}}}}},
		{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": map[string]any{"name": "get_network_policy", "arguments": map[string]any{"tenant": "testing"}}},
	}
	var stdin bytes.Buffer
	encoder := json.NewEncoder(&stdin)
	for _, req := range requests {
		if err := encoder.Encode(req); err != nil {
			t.Fatal(err)
		}
	}
	executable, _ := os.Executable()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestTenantAccessMCPHelper$")
	command.Env = append(os.Environ(), "CONTAINARIUM_TEST_TENANT_MCP="+server.URL, "CONTAINARIUM_MCP_ALLOW_INSECURE=true")
	command.Stdin = &stdin
	var stderr bytes.Buffer
	command.Stderr = &stderr
	stdout, err := command.Output()
	if err != nil {
		t.Fatalf("MCP helper: %v %s", err, stderr.String())
	}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	count := 0
	for scanner.Scan() {
		var response mcp.MCPResponse
		if err := json.Unmarshal(scanner.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Error != nil {
			t.Fatalf("MCP protocol error: %v", response.Error)
		}
		if bytes.Contains(scanner.Bytes(), []byte(`"isError":true`)) {
			t.Fatalf("MCP tool error: %s", scanner.Bytes())
		}
		count++
	}
	if count != 5 {
		t.Fatalf("expected initialize, tools/list and three actual call results; got %d", count)
	}
	current, err := s.store.Get(context.Background(), "testing")
	if err != nil || len(current.AllowFromTenants) != 1 || current.AllowFromTenants[0] != "allinone" {
		t.Fatalf("actual MCP tools/call did not mutate the isolated store: %v", err)
	}
}
func TestTenantAccessMCPHelper(t *testing.T) {
	target := os.Getenv("CONTAINARIUM_TEST_TENANT_MCP")
	if target == "" {
		return
	}
	s, err := mcp.NewServer(&mcp.Config{ServerURL: target, JWTToken: "synthetic-test-token", MCPTools: "network_tenant_capabilities,list_network_policies,get_network_policy,patch_tenant_access"})
	if err == nil {
		err = s.Start()
	}
	if err != nil {
		_, _ = io.WriteString(os.Stderr, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}
