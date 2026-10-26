package server

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/proofpack"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const (
	// maxVerifyPackBytes bounds the encoded sealed pack VerifyProofPack
	// accepts. The pack is client-supplied, so it is bounded here as well as
	// by the transport's own receive limit.
	maxVerifyPackBytes = 4 << 20
	// verifyTimeout bounds the chain walk, which is linear in the rows
	// between the seal row and the tip.
	verifyTimeout = 2 * time.Minute
)

// ProofPackServer implements ProofPackService (#3064).
type ProofPackServer struct {
	pb.UnimplementedProofPackServiceServer
	chain proofpack.SealChain
}

// NewProofPackServer returns the service backed by the audit chain. A nil
// chain makes VerifyProofPack return Unavailable.
func NewProofPackServer(chain proofpack.SealChain) *ProofPackServer {
	return &ProofPackServer{chain: chain}
}

// VerifyProofPack runs proofpack.Verify, the check `containarium proof-pack
// verify` runs, and maps its outcome to the typed response.
func (s *ProofPackServer) VerifyProofPack(ctx context.Context, req *pb.VerifyProofPackRequest) (*pb.VerifyProofPackResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeAuditRead); err != nil {
		return nil, err
	}
	if s.chain == nil {
		return nil, status.Error(codes.Unavailable, "audit store is not available on this daemon")
	}
	sealed := req.GetSealed()
	if sealed.GetPack() == nil || sealed.GetSeal() == nil || sealed.GetSeal().GetAuditRowId() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "sealed must hold a pack and a seal with an audit_row_id")
	}
	if n := len(sealed.GetPack().GetSteps()); n > proofpack.MaxSteps {
		return nil, status.Errorf(codes.InvalidArgument, "pack has %d steps, max %d", n, proofpack.MaxSteps)
	}
	if n := proto.Size(sealed); n > maxVerifyPackBytes {
		return nil, status.Errorf(codes.InvalidArgument, "sealed pack is %d bytes, max %d", n, maxVerifyPackBytes)
	}

	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	res, err := proofpack.Verify(ctx, s.chain, sealed)
	if err == nil {
		return &pb.VerifyProofPackResponse{
			Ok:           true,
			Verdict:      pb.ProofPackVerdict_PROOF_PACK_VERDICT_OK,
			PackSha256:   res.PackSHA256,
			AuditRowId:   res.AuditRowID,
			StepsChecked: int32(res.Steps), // #nosec G115 -- bounded by MaxSteps
			ChainTipId:   res.ChainCheckedThrough,
			ChainTipHash: res.ChainTipHash,
		}, nil
	}

	resp := &pb.VerifyProofPackResponse{Message: err.Error()}
	var tp *proofpack.TamperedPart
	switch {
	case errors.As(err, &tp):
		resp.Verdict = pb.ProofPackVerdict_PROOF_PACK_VERDICT_MISMATCH
		resp.FirstMismatch = &pb.ProofMismatch{Header: tp.Step == proofpack.HeaderPart, Name: tp.Name, Reason: tp.Reason}
		if tp.Step != proofpack.HeaderPart {
			resp.FirstMismatch.StepIndex = int32(tp.Step) // #nosec G115 -- bounded by MaxSteps
		}
	case errors.Is(err, proofpack.ErrSealPurged):
		resp.Verdict = pb.ProofPackVerdict_PROOF_PACK_VERDICT_SEAL_PURGED
	case errors.Is(err, proofpack.ErrSealNotFound):
		resp.Verdict = pb.ProofPackVerdict_PROOF_PACK_VERDICT_SEAL_NOT_FOUND
	case errors.Is(err, proofpack.ErrChainBroken):
		resp.Verdict = pb.ProofPackVerdict_PROOF_PACK_VERDICT_CHAIN_BROKEN
	default:
		// A storage failure, not a verdict about the pack.
		return nil, status.Errorf(codes.Unavailable, "verify proof pack: %v", err)
	}
	return resp, nil
}
