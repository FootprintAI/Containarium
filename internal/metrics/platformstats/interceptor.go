package platformstats

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// UnaryInterceptor returns a grpc.UnaryServerInterceptor that classifies
// every completed unary RPC by its final gRPC status and records one
// event into stats — the single choke point where both native gRPC
// clients and REST-via-grpc-gateway callers converge, so counting here
// covers both transports with no double counting.
//
// Purely observational: it never alters the request, the response, or
// the error the wrapped handler returns, and it never fails a call — a
// nil stats would panic, so callers must always pass a real *Stats.
func UnaryInterceptor(stats *Stats) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		resp, err := handler(ctx, req)
		stats.RecordAPIRequest(ClassifyCode(status.Code(err)))
		return resp, err
	}
}
