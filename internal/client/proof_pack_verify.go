package client

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3064 — typed client for ProofPackService.VerifyProofPack, on both
// transports. A pack that fails verification is a normal response
// (ok=false), not an error; errors are transport, auth and malformed-input
// failures.

// VerifyProofPack asks the daemon to verify a sealed pack over REST.
func (c *HTTPClient) VerifyProofPack(ctx context.Context, sealed *pb.SealedProofPack) (*pb.VerifyProofPackResponse, error) {
	body, err := protojson.Marshal(&pb.VerifyProofPackRequest{Sealed: sealed})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	resp, err := c.doRequest(ctx, http.MethodPost, "/v1/proof-packs/verify", body)
	if err != nil {
		return nil, fmt.Errorf("verify proof pack: %w", err)
	}
	defer drainClose(resp)
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("verify proof pack: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("verify proof pack: HTTP %d: %s", resp.StatusCode, b)
	}
	var out pb.VerifyProofPackResponse
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("verify proof pack: decode response: %w", err)
	}
	return &out, nil
}

// VerifyProofPack is the gRPC transport's counterpart.
func (c *GRPCClient) VerifyProofPack(ctx context.Context, sealed *pb.SealedProofPack) (*pb.VerifyProofPackResponse, error) {
	resp, err := c.proofPackClient.VerifyProofPack(ctx, &pb.VerifyProofPackRequest{Sealed: sealed})
	if err != nil {
		return nil, fmt.Errorf("verify proof pack: %w", err)
	}
	return resp, nil
}
