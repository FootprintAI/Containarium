package client

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The whole-box restore contract over both transports (#3356): the typed
// gRPC and HTTP client methods deliver every request field to the server and
// return its response.

type restoreBoxClient interface {
	RestoreBoxBackup(req *pb.RestoreBoxBackupRequest) (*pb.RestoreBoxBackupResponse, error)
}

// fakeRestoreBoxServer records the request it received and answers with a
// fixed response.
type fakeRestoreBoxServer struct {
	pb.UnimplementedBackupServiceServer
	got *pb.RestoreBoxBackupRequest
}

func (f *fakeRestoreBoxServer) RestoreBoxBackup(_ context.Context, req *pb.RestoreBoxBackupRequest) (*pb.RestoreBoxBackupResponse, error) {
	f.got = req
	return &pb.RestoreBoxBackupResponse{Message: "restore complete: " + req.GetId(), Box: req.GetTargetBox()}, nil
}

func restoreBoxTransports(t *testing.T) map[string]struct {
	client restoreBoxClient
	fake   *fakeRestoreBoxServer
} {
	t.Helper()
	grpcFake := &fakeRestoreBoxServer{}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	pb.RegisterBackupServiceServer(gs, grpcFake)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	g, err := NewGRPCClient(lis.Addr().String(), "", true)
	if err != nil {
		t.Fatalf("NewGRPCClient: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })

	httpFake := &fakeRestoreBoxServer{}
	mux := runtime.NewServeMux()
	if err := pb.RegisterBackupServiceHandlerServer(context.Background(), mux, httpFake); err != nil {
		t.Fatalf("register gateway handler: %v", err)
	}
	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)
	h, err := NewHTTPClient(hs.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	return map[string]struct {
		client restoreBoxClient
		fake   *fakeRestoreBoxServer
	}{
		"grpc": {g, grpcFake},
		"rest": {h, httpFake},
	}
}

func TestRestoreBoxBackup_TransportsDeliverEveryField(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *pb.RestoreBoxBackupRequest
	}{
		{"named target with force and identity", &pb.RestoreBoxBackupRequest{
			// A space and a plus in the id must survive the REST path.
			Id:          "alice-box 20261101T000000Z+1",
			TargetBox:   "alice-copy",
			Force:       true,
			AgeIdentity: "AGE-SECRET-KEY-1FAKEFIXTUREIDENTITY",
		}},
		{"default target, no force", &pb.RestoreBoxBackupRequest{Id: "alice-box-20261101T000000Z"}},
	} {
		for name, tr := range restoreBoxTransports(t) {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				resp, err := tr.client.RestoreBoxBackup(tc.req)
				if err != nil {
					t.Fatalf("RestoreBoxBackup: %v", err)
				}
				if !proto.Equal(tr.fake.got, tc.req) {
					t.Fatalf("server got %v, want %v", tr.fake.got, tc.req)
				}
				if resp.GetMessage() != "restore complete: "+tc.req.GetId() || resp.GetBox() != tc.req.GetTargetBox() {
					t.Fatalf("response = %v", resp)
				}
			})
		}
	}
}

func TestRestoreBoxBackup_ErrorNeverEchoesIdentity(t *testing.T) {
	const identity = "AGE-SECRET-KEY-1FAKEFIXTUREIDENTITY"
	// A server that does not implement the RPC: both transports return an
	// error, and neither error text carries the identity.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	pb.RegisterBackupServiceServer(gs, &pb.UnimplementedBackupServiceServer{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	g, err := NewGRPCClient(lis.Addr().String(), "", true)
	if err != nil {
		t.Fatalf("NewGRPCClient: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })
	mux := runtime.NewServeMux()
	if err := pb.RegisterBackupServiceHandlerServer(context.Background(), mux, &pb.UnimplementedBackupServiceServer{}); err != nil {
		t.Fatalf("register gateway handler: %v", err)
	}
	hs := httptest.NewServer(http.Handler(mux))
	t.Cleanup(hs.Close)
	h, err := NewHTTPClient(hs.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	for name, c := range map[string]restoreBoxClient{"grpc": g, "rest": h} {
		t.Run(name, func(t *testing.T) {
			_, err := c.RestoreBoxBackup(&pb.RestoreBoxBackupRequest{Id: "alice-box-1", AgeIdentity: identity})
			if err == nil {
				t.Fatal("RestoreBoxBackup against an unimplemented server succeeded")
			}
			if strings.Contains(err.Error(), identity) {
				t.Fatalf("error %q echoes the age identity", err)
			}
		})
	}
}
