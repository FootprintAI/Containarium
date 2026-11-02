package server

import (
	"google.golang.org/grpc"

	"github.com/footprintai/containarium/internal/grpcrecover"
)

// recoveryUnaryInterceptor / recoveryStreamInterceptor keep the server
// package's existing names; the implementation is shared with the sentinel and
// agent-box gRPC servers.
func recoveryUnaryInterceptor() grpc.UnaryServerInterceptor   { return grpcrecover.Unary() }
func recoveryStreamInterceptor() grpc.StreamServerInterceptor { return grpcrecover.Stream() }
