package server

import (
	"context"
	"errors"
	"log"
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
	// maxConcurrentVerifies bounds the chain walks running at once; a caller
	// over the cap is refused, not queued.
	maxConcurrentVerifies = 4
)

// The messages a response carries, one per verdict. The audit chain is
// global, so a response never says which row, base id, date or underlying
// error was behind the verdict; that goes to the daemon log only.
const (
	msgSealPurged   = "the seal's audit row is not in the chain (purged by retention, or never issued); the pack cannot be checked against the chain"
	msgSealNotFound = "no audit row is the seal of this pack"
	msgChainBroken  = "the audit chain does not verify from the seal to the tip"
	msgMismatch     = "the pack does not match its seal"
)

// ProofPackServer implements ProofPackService (#3064).
type ProofPackServer struct {
	pb.UnimplementedProofPackServiceServer
	chain proofpack.SealChain
	slots chan struct{}
}

// NewProofPackServer returns the service backed by the audit chain. A nil
// chain makes VerifyProofPack return Unavailable.
func NewProofPackServer(chain proofpack.SealChain) *ProofPackServer {
	return &ProofPackServer{chain: chain, slots: make(chan struct{}, maxConcurrentVerifies)}
}

// VerifyProofPack runs proofpack.Verify, the check `containarium proof-pack
// verify` runs, and maps its outcome to the typed response.
func (s *ProofPackServer) VerifyProofPack(ctx context.Context, req *pb.VerifyProofPackRequest) (*pb.VerifyProofPackResponse, error) {
	// The same gate as GET /v1/audit/logs: the admin role, or an explicit
	// audit:read scope. A token with no scopes claim does not pass by being
	// unrestricted.
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeAuditRead); err != nil {
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

	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return nil, status.Error(codes.ResourceExhausted, "too many proof pack verifications in progress; retry shortly")
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

	log.Printf("proof pack verify: %v", err)
	resp := &pb.VerifyProofPackResponse{}
	var tp *proofpack.TamperedPart
	switch {
	case errors.As(err, &tp):
		resp.Verdict = pb.ProofPackVerdict_PROOF_PACK_VERDICT_MISMATCH
		resp.Message = msgMismatch
		reason := tp.Public
		if reason == "" {
			reason = "does not match the seal"
		}
		resp.FirstMismatch = &pb.ProofMismatch{Header: tp.Step == proofpack.HeaderPart, Name: tp.Name, Reason: reason}
		if tp.Step != proofpack.HeaderPart {
			resp.FirstMismatch.StepIndex = int32(tp.Step) // #nosec G115 -- bounded by MaxSteps
		}
	case errors.Is(err, proofpack.ErrSealPurged):
		resp.Verdict = pb.ProofPackVerdict_PROOF_PACK_VERDICT_SEAL_PURGED
		resp.Message = msgSealPurged
	case errors.Is(err, proofpack.ErrSealNotFound):
		resp.Verdict = pb.ProofPackVerdict_PROOF_PACK_VERDICT_SEAL_NOT_FOUND
		resp.Message = msgSealNotFound
	case errors.Is(err, proofpack.ErrChainBroken):
		resp.Verdict = pb.ProofPackVerdict_PROOF_PACK_VERDICT_CHAIN_BROKEN
		resp.Message = msgChainBroken
	default:
		// A storage failure, not a verdict about the pack. The detail
		// (driver text, table names) stays in the log.
		return nil, status.Error(codes.Unavailable, "the audit store could not be read; retry later")
	}
	return resp, nil
}
