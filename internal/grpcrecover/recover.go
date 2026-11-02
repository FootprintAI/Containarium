// Package grpcrecover turns a panic in a gRPC handler into an Internal error.
// grpc-go does not recover handler panics itself, so without these a single
// bad request terminates the whole process.
package grpcrecover

import (
	"context"
	"log"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Unary recovers a panic in a unary handler or an inner interceptor. Put it
// first (outermost) in the chain so it covers the others too.
func Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("panic recovered in %s: %v\n%s", info.FullMethod, r, debug.Stack())
				err = status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

// Stream is the streaming counterpart of Unary.
func Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("panic recovered in %s: %v\n%s", info.FullMethod, r, debug.Stack())
				err = status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(srv, ss)
	}
}
