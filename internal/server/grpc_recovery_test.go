package server

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestRecoveryUnaryInterceptor_PanicBecomesInternal(t *testing.T) {
	_, err := recoveryUnaryInterceptor()(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/t/Panic"},
		func(context.Context, any) (any, error) { panic("boom") })
	if status.Code(err) != codes.Internal {
		t.Fatalf("want Internal, got %v", err)
	}
}

func TestRecoveryUnaryInterceptor_PassThrough(t *testing.T) {
	resp, err := recoveryUnaryInterceptor()(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/t/Ok"},
		func(context.Context, any) (any, error) { return "ok", nil })
	if err != nil || resp != "ok" {
		t.Fatalf("got %v, %v", resp, err)
	}
}

func TestRecoveryStreamInterceptor_PanicBecomesInternal(t *testing.T) {
	err := recoveryStreamInterceptor()(nil, nil,
		&grpc.StreamServerInfo{FullMethod: "/t/Panic"},
		func(any, grpc.ServerStream) error { panic("boom") })
	if status.Code(err) != codes.Internal {
		t.Fatalf("want Internal, got %v", err)
	}
}

func TestTrafficGetConnections_NegativeLimitRejected(t *testing.T) {
	srv := &TrafficServer{}
	_, err := srv.GetConnections(tenantCtx("alice"), &pb.GetConnectionsRequest{ContainerName: "alice-container", Limit: -1})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v want InvalidArgument", err)
	}
}
