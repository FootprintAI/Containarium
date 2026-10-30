package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/metrics/platformstats"
	"github.com/footprintai/containarium/pkg/core/box"
	boxlxc "github.com/footprintai/containarium/pkg/core/box/lxc"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"
)

// No real instance or host user is created: the server reaches a backend that
// captures the spec and returns a simulated Guard failure. Positive lifecycle
// and actual ACL attachment are tested separately against fake Incus backends.
type nativeTransportBackend struct {
	incus.Backend
	info incus.ContainerInfo
}

func (b *nativeTransportBackend) ListContainers() ([]incus.ContainerInfo, error) {
	return []incus.ContainerInfo{b.info}, nil
}
func (b *nativeTransportBackend) GetContainer(string) (*incus.ContainerInfo, error) {
	out := b.info
	return &out, nil
}

type nativeTransportBoxes struct {
	box.BoxBackend
	last box.BoxSpec
}

func (b *nativeTransportBoxes) Kind() box.BackendKind { return box.KindLXC }
func (b *nativeTransportBoxes) Create(_ context.Context, spec box.BoxSpec) (*box.BoxStatus, error) {
	b.last = spec
	return nil, errors.Join(container.ErrNICGuard, errors.New("fixture guard failure; no instance created"))
}
func TestNativeTenantAuthenticatedRESTAndGRPC(t *testing.T) {
	backend := &nativeTransportBackend{info: incus.ContainerInfo{Name: "workload-container", Username: "workload", Tenant: "observed-team", State: "Running"}}
	mgr := container.NewWithBackend(backend)
	capture := &nativeTransportBoxes{}
	cs := &ContainerServer{manager: mgr, boxBackend: boxlxc.New(mgr), nativeTenantReady: func() bool { return true }, platformStats: platformstats.New()}
	ns := &NetworkServer{nativeTenantLocal: true, nativeTenantReady: func() bool { return true }}
	tm, err := auth.NewTokenManager(strings.Repeat("fixture-key-", 4), "native-tenant-test")
	if err != nil {
		t.Fatal(err)
	}
	token, err := tm.GenerateToken("operator", []string{auth.RoleAdmin}, time.Minute, auth.ScopeContainersRead, auth.ScopeContainersWrite)
	if err != nil {
		t.Fatal(err)
	}
	// HTTP uses the production JWT middleware and generated gateway. Metadata
	// created by that middleware is forwarded into the in-process gRPC service.
	mux := runtime.NewServeMux(runtime.WithMetadata(func(ctx context.Context, _ *http.Request) metadata.MD {
		md, _ := metadata.FromOutgoingContext(ctx)
		return md
	}))
	if err := pb.RegisterContainerServiceHandlerServer(context.Background(), mux, cs); err != nil {
		t.Fatal(err)
	}
	if err := pb.RegisterNetworkServiceHandlerServer(context.Background(), mux, ns); err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(auth.NewAuthMiddleware(tm).HTTPMiddleware(mux))
	defer httpServer.Close()
	request := func(method, path, body, credential string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, httpServer.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if credential != "" {
			req.Header.Set("Authorization", "Bearer "+credential)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var raw bytes.Buffer
		if _, err := raw.ReadFrom(resp.Body); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, raw.Bytes()
	}
	for _, path := range []string{"/v1/network-tenants/capabilities", "/v1/containers", "/v1/containers/workload"} {
		if code, _ := request("GET", path, "", ""); code != 401 {
			t.Fatalf("unauthenticated %s: %d", path, code)
		}
		code, raw := request("GET", path, "", token)
		if code != 200 {
			t.Fatalf("%s: %d %s", path, code, raw)
		}
		if path != "/v1/network-tenants/capabilities" && !bytes.Contains(raw, []byte("observed-team")) {
			t.Fatalf("Provider identity missing: %s", raw)
		}
	}
	code, raw := request("POST", "/v1/containers", `{"username":"workload","networkTenant":"team-a","tenantId":"default","dryRun":true}`, token)
	if code != 200 || !bytes.Contains(raw, []byte(`"dryRun":true`)) {
		t.Fatalf("REST preflight: %d %s", code, raw)
	}
	userToken, err := tm.GenerateToken("workload", []string{"user"}, time.Minute, auth.ScopeContainersWrite)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := request("POST", "/v1/containers", `{"username":"workload","networkTenant":"team-a","dryRun":true}`, userToken); code != 403 {
		t.Fatalf("non-admin accepted: %d", code)
	}
	// Full Create reaches the actual authorized server->BoxSpec path. Its guard
	// failure maps to FAILED_PRECONDITION before post-create host-side work.
	cs.boxBackend = capture
	code, raw = request("POST", "/v1/containers", `{"username":"workload","networkTenant":"team-a","tenantId":"default"}`, token)
	if code != 400 || capture.last.NetworkTenant != "team-a" || capture.last.Ref.Tenant != "workload" {
		t.Fatalf("spec propagation: %d %s %+v", code, raw, capture.last)
	}
	cs.boxBackend = boxlxc.New(mgr)
	// Same generated gRPC contract, with real signed-token validation at the edge.
	listener := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		tokens := md.Get("authorization")
		if len(tokens) != 1 {
			return nil, status.Error(codes.Unauthenticated, "token required")
		}
		claims, err := tm.ValidateAccessToken(strings.TrimPrefix(tokens[0], "Bearer "))
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		return next(auth.ContextWithClaims(ctx, claims), req)
	}))
	pb.RegisterContainerServiceServer(srv, cs)
	pb.RegisterNetworkServiceServer(srv, ns)
	go func() { _ = srv.Serve(listener) }()
	defer srv.Stop()
	conn, err := grpc.NewClient("passthrough:///fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	response, err := pb.NewContainerServiceClient(conn).CreateContainer(ctx, &pb.CreateContainerRequest{Username: "workload", NetworkTenant: "team-a", TenantId: "default", DryRun: true})
	if err != nil || !response.GetDryRun() {
		t.Fatalf("gRPC create: %v", err)
	}
	observed, err := pb.NewContainerServiceClient(conn).GetContainer(ctx, &pb.GetContainerRequest{Username: "workload"})
	if err != nil || observed.GetContainer().GetNetworkTenant() != "observed-team" {
		t.Fatalf("gRPC readback %v %v", observed, err)
	}
	caps, err := pb.NewNetworkServiceClient(conn).GetNetworkTenantCapabilities(ctx, &pb.GetNetworkTenantCapabilitiesRequest{})
	if err != nil || !caps.SharedTenantCreate || caps.AtomicTenantAccess || caps.NetworkPolicyWrite {
		t.Fatalf("caps %v %v", caps, err)
	}
	// JSON uses camelCase names and typed source enum values.
	raw, err = protojson.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("NETWORK_TENANT_SOURCE_NATIVE")) {
		t.Fatal(string(raw))
	}
}
