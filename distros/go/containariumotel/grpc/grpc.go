package grpc

import (
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc/stats"
)

// NewServerHandler returns a stats.Handler that emits OTel gRPC server
// telemetry using the global MeterProvider + TracerProvider set up by
// containariumotel.Init.
//
// otelgrpc options can be passed through to tune things like the
// span name formatter or the public-endpoint filter; in most apps
// the zero-option default is what you want.
func NewServerHandler(opts ...otelgrpc.Option) stats.Handler {
	return otelgrpc.NewServerHandler(opts...)
}

// NewClientHandler returns a stats.Handler for gRPC clients. Same
// global-provider semantics as NewServerHandler.
func NewClientHandler(opts ...otelgrpc.Option) stats.Handler {
	return otelgrpc.NewClientHandler(opts...)
}
