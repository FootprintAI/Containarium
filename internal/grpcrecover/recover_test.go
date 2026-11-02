package grpcrecover

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUnaryRecoversPanic(t *testing.T) {
	_, err := Unary()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/t/P"},
		func(context.Context, any) (any, error) { panic("boom") })
	if status.Code(err) != codes.Internal {
		t.Fatalf("got %v want Internal", err)
	}
}

func TestUnaryPassesThrough(t *testing.T) {
	resp, err := Unary()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/t/O"},
		func(context.Context, any) (any, error) { return "ok", nil })
	if err != nil || resp != "ok" {
		t.Fatalf("got %v, %v", resp, err)
	}
}

func TestStreamRecoversPanic(t *testing.T) {
	err := Stream()(nil, nil, &grpc.StreamServerInfo{FullMethod: "/t/P"},
		func(any, grpc.ServerStream) error { panic("boom") })
	if status.Code(err) != codes.Internal {
		t.Fatalf("got %v want Internal", err)
	}
}
