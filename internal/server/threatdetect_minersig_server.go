package server

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// List/Add/RemoveMinerSignature (#2638) — the miner-signature list the
// miner-signature rule matches execs against. Same gates as the
// bad-destination verbs: reading needs security:read; mutating needs
// security:write AND the admin role, because the list protects the whole
// fleet and removing an entry silently disables a detection.

// SetMinerSignatureRule wires the rule. nil (construction failed) makes the
// handlers report Unavailable.
func (s *ThreatDetectionServer) SetMinerSignatureRule(r *threatdetect.MinerSignatureRule) {
	s.minerSigRule = r
}

// ListMinerSignatures returns baseline then operator entries.
func (s *ThreatDetectionServer) ListMinerSignatures(ctx context.Context, _ *pb.ListMinerSignaturesRequest) (*pb.ListMinerSignaturesResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityRead); err != nil {
		return nil, err
	}
	if s.minerSigRule == nil {
		return nil, status.Errorf(codes.Unavailable, "miner-signature rule not available")
	}
	entries := s.minerSigRule.ListSignatures()
	out := make([]*pb.MinerSignature, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.ToProto())
	}
	return &pb.ListMinerSignaturesResponse{Signatures: out, BaselineVersion: s.minerSigRule.BaselineVersion()}, nil
}

// AddMinerSignature adds an operator entry, effective immediately.
func (s *ThreatDetectionServer) AddMinerSignature(ctx context.Context, req *pb.AddMinerSignatureRequest) (*pb.AddMinerSignatureResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityWrite); err != nil {
		return nil, err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if s.minerSigRule == nil {
		return nil, status.Errorf(codes.Unavailable, "miner-signature rule not available")
	}
	sig := req.GetSignature()
	if sig == nil || sig.GetPattern() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "signature.kind and signature.pattern are required")
	}
	entry, err := s.minerSigRule.AddSignature(ctx, sig.GetKind(), sig.GetPattern(), sig.GetLabel())
	if err != nil {
		switch {
		case errors.Is(err, threatdetect.ErrMinerSignatureBuiltin):
			return nil, status.Errorf(codes.AlreadyExists, "%v", err)
		case errors.Is(err, threatdetect.ErrMinerSignatureInvalid):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "add miner signature: %v", err)
	}
	return &pb.AddMinerSignatureResponse{Signature: entry.ToProto()}, nil
}

// RemoveMinerSignature removes an operator entry; baseline entries are
// refused with FailedPrecondition, an unknown entry is NotFound.
func (s *ThreatDetectionServer) RemoveMinerSignature(ctx context.Context, req *pb.RemoveMinerSignatureRequest) (*pb.RemoveMinerSignatureResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityWrite); err != nil {
		return nil, err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if s.minerSigRule == nil {
		return nil, status.Errorf(codes.Unavailable, "miner-signature rule not available")
	}
	if req.GetPattern() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "kind and pattern are required")
	}
	err := s.minerSigRule.RemoveSignature(ctx, req.GetKind(), req.GetPattern())
	switch {
	case err == nil:
		return &pb.RemoveMinerSignatureResponse{}, nil
	case errors.Is(err, threatdetect.ErrMinerSignatureInvalid):
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	case errors.Is(err, threatdetect.ErrMinerSignatureNotFound):
		return nil, status.Errorf(codes.NotFound, "%v", err)
	case errors.Is(err, threatdetect.ErrMinerSignatureBuiltin):
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	default:
		return nil, status.Errorf(codes.Internal, "remove miner signature: %v", err)
	}
}
