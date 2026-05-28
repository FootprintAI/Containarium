// Package grpc provides Containarium-flavored gRPC instrumentation.
//
// It's a thin re-export of go.opentelemetry.io/contrib/instrumentation/
// google.golang.org/grpc/otelgrpc as a sub-package per decision D11 —
// shipped separately so the gRPC transitive dependency only lands in
// modules that import this package, not in HTTP-only callers of the
// parent distro.
//
// Usage on the server side:
//
//	import containariumgrpc "github.com/footprintai/containarium/distros/go/containariumotel/grpc"
//	import "google.golang.org/grpc"
//
//	s := grpc.NewServer(grpc.StatsHandler(containariumgrpc.NewServerHandler()))
//
// Usage on the client side:
//
//	conn, err := grpc.Dial(addr,
//	    grpc.WithStatsHandler(containariumgrpc.NewClientHandler()),
//	    grpc.WithTransportCredentials(...),
//	)
//
// MeterProvider and TracerProvider default to whatever was set globally
// by containariumotel.Init(), so a single Init() call sets both HTTP
// and gRPC instrumentation up consistently.
package grpc
