package client

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/retention"
	"github.com/footprintai/containarium/internal/server"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The retention contract over both transports (#2875): the REST shim
// (org id in the path) and gRPC reach the same RetentionServer and agree.

type retentionClient interface {
	GetRetentionPolicy() (*pb.GetRetentionPolicyResponse, error)
	SetRetentionPolicy(req *pb.SetRetentionPolicyRequest) (*pb.SetRetentionPolicyResponse, error)
	ListLegalHolds() (*pb.ListLegalHoldsResponse, error)
	SetLegalHold(req *pb.SetLegalHoldRequest) (*pb.SetLegalHoldResponse, error)
	ReleaseLegalHold(orgID string) (*pb.ReleaseLegalHoldResponse, error)
}

func retentionTransports(t *testing.T) map[string]retentionClient {
	t.Helper()
	admin := func(ctx context.Context) context.Context { return auth.ContextWithClaims(ctx, gpClaims(true)) }

	grpcSrv := server.NewRetentionServer(retention.NewMemoryStore())
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		return h(admin(ctx), req)
	}))
	pb.RegisterRetentionServiceServer(gs, grpcSrv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	g, err := NewGRPCClient(lis.Addr().String(), "", true)
	if err != nil {
		t.Fatalf("NewGRPCClient: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })

	mux := runtime.NewServeMux()
	if err := pb.RegisterRetentionServiceHandlerServer(context.Background(), mux, server.NewRetentionServer(retention.NewMemoryStore())); err != nil {
		t.Fatalf("register gateway handler: %v", err)
	}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(admin(r.Context())))
	}))
	t.Cleanup(hs.Close)
	h, err := NewHTTPClient(hs.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	return map[string]retentionClient{"grpc": g, "rest": h}
}

func TestRetentionTransports_Agree(t *testing.T) {
	for name, c := range retentionTransports(t) {
		t.Run(name, func(t *testing.T) {
			if _, err := c.SetRetentionPolicy(&pb.SetRetentionPolicyRequest{Windows: []*pb.RetentionWindow{
				{Class: pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS, Days: 120},
			}}); err != nil {
				t.Fatalf("SetRetentionPolicy: %v", err)
			}
			p, err := c.GetRetentionPolicy()
			if err != nil {
				t.Fatalf("GetRetentionPolicy: %v", err)
			}
			if w := p.GetPolicy().GetWindows()[2]; w.GetClass() != pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS || w.GetDays() != 120 {
				t.Fatalf("gateway logs window = %v, want 120 days", w)
			}
			// An org id with a space and a plus proves the path escaping round-trips.
			const org = "org a+b"
			if _, err := c.SetLegalHold(&pb.SetLegalHoldRequest{OrgId: org, Reason: "case 7"}); err != nil {
				t.Fatalf("SetLegalHold: %v", err)
			}
			holds, err := c.ListLegalHolds()
			if err != nil || len(holds.GetHolds()) != 1 || holds.GetHolds()[0].GetOrgId() != org || holds.GetHolds()[0].GetReason() != "case 7" {
				t.Fatalf("ListLegalHolds = (%v, %v), want the hold on %q", holds, err, org)
			}
			if r, err := c.ReleaseLegalHold(org); err != nil || r.GetHold().GetOrgId() != org {
				t.Fatalf("ReleaseLegalHold = (%v, %v)", r, err)
			}
			if _, err := c.ReleaseLegalHold(org); err == nil {
				t.Fatal("releasing a released hold succeeded")
			}
		})
	}
}
