// Package guardrail drives a detection engine over a set of text units,
// redacts what it flagged, re-scans the result as the gate, and signs an
// attestation a consumer can verify before it touches the data
// (docs/architecture/guardrail.md).
//
// The package detects nothing itself. Every finding comes from an Engine;
// the in-tree RulesEngine is a reference implementation so the flow is
// runnable without any external process, not a product detector.
package guardrail

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Engine is anything that can scan text units: the gRPC client over a
// process implementing GuardrailEngineService, or the reference rules
// engine. Offsets in the findings are Unicode code points into the unit's
// text (proto/containarium/v1/guardrail.proto).
type Engine interface {
	Scan(ctx context.Context, req *pb.GuardrailScanRequest) (*pb.GuardrailScanResponse, error)
}

// grpcEngine is the thin client over a remote GuardrailEngineService.
type grpcEngine struct {
	client pb.GuardrailEngineServiceClient
}

// NewGRPCEngine wraps an established connection to an engine process.
func NewGRPCEngine(conn grpc.ClientConnInterface) Engine {
	return &grpcEngine{client: pb.NewGuardrailEngineServiceClient(conn)}
}

func (e *grpcEngine) Scan(ctx context.Context, req *pb.GuardrailScanRequest) (*pb.GuardrailScanResponse, error) {
	return e.client.Scan(ctx, req)
}
