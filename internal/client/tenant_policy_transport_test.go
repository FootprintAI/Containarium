package client

import (
	"context"
	"errors"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTenantReviewUnknownFieldsAndAbsentPolicyHTTP(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/network-tenants/capabilities":
			w.Write([]byte(`{"contract":"native-network-tenant/v1","backendScope":"local-lxc","nativeMembershipRead":true,"sharedTenantCreate":true,"futureFlag":true}`))
		case "/v1/network-policies/missing":
			http.NotFound(w, r)
		case "/v1/network-policies/team-a":
			w.Write([]byte(`{"policy":{"tenant":"team-a","futurePolicyFlag":true},"revision":"fixture","futureFlag":true}`))
		case "/v1/network-policies/tenant-access":
			w.Write([]byte(`{"futureFlag":true}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer fixture.Close()
	c, err := NewHTTPClient(fixture.URL, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	cap, err := c.GetNetworkTenantCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	if err = requireNativeTenantCapability(cap); err != nil {
		t.Fatal(err)
	}
	if _, err = c.GetNetworkPolicy("missing"); !errors.Is(err, ErrNetworkPolicyAbsent) {
		t.Fatal(err)
	}
	if p, err := c.GetNetworkPolicy("team-a"); err != nil || p.GetRevision() != "fixture" {
		t.Fatalf("%v %v", p, err)
	}
	if _, err = c.PatchTenantAccess(&pb.PatchTenantAccessRequest{}); err != nil {
		t.Fatal(err)
	}
	if networkTenantSourceFromProto(pb.NetworkTenantSource_NETWORK_TENANT_SOURCE_UNSPECIFIED) != "" {
		t.Fatal("zero source is not empty")
	}
}

type reviewPolicyFixture struct {
	pb.UnimplementedNetworkPolicyServiceServer
	received *pb.PatchTenantAccessRequest
}

func (f *reviewPolicyFixture) GetNetworkPolicy(context.Context, *pb.GetNetworkPolicyRequest) (*pb.GetNetworkPolicyResponse, error) {
	return nil, status.Error(codes.NotFound, "absent")
}
func (f *reviewPolicyFixture) PatchTenantAccess(_ context.Context, r *pb.PatchTenantAccessRequest) (*pb.PatchTenantAccessResponse, error) {
	f.received = r
	return &pb.PatchTenantAccessResponse{}, nil
}
func TestTenantReviewTypedPolicyGRPC(t *testing.T) {
	f := &reviewPolicyFixture{}
	l := bufconn.Listen(1 << 20)
	s := grpc.NewServer()
	pb.RegisterNetworkPolicyServiceServer(s, f)
	go func() { _ = s.Serve(l) }()
	defer s.Stop()
	conn, err := grpc.NewClient("passthrough:///fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return l.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	c := &GRPCClient{networkPolicyClient: pb.NewNetworkPolicyServiceClient(conn)}
	if _, err = c.GetNetworkPolicy("missing"); !errors.Is(err, ErrNetworkPolicyAbsent) {
		t.Fatal(err)
	}
	req := &pb.PatchTenantAccessRequest{Changes: []*pb.TenantAccessChange{{Destination: "team-a", AddSources: []string{"team-b"}, ExpectedRevision: "absent"}}}
	if _, err = c.PatchTenantAccess(req); err != nil {
		t.Fatal(err)
	}
	if f.received.GetChanges()[0].GetDestination() != "team-a" {
		t.Fatal(f.received)
	}
}
