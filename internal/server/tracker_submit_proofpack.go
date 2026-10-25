package server

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/proofpack"
	"github.com/footprintai/containarium/internal/runlease"
	"github.com/footprintai/containarium/internal/tracker/submit"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Proof Pack on the submit path (#2798, slice 2 of #2366). Before the change
// is pushed, the daemon generates the run's Proof Pack in the run's box,
// seals it into the audit hash chain, and the pushed branch carries it as
// proofpack.AttachPath; the description carries its digest. A change is
// never opened without its pack.
//
// The pack is produced in the run's own box for now. #2799 moves production
// to a box other than the coder's.

// proofPackExecerForSubmit is proofPackExecer if a test set one, otherwise
// s.manager, or nil when neither is configured (never a typed nil).
func (s *ContainerServer) proofPackExecerForSubmit() proofpack.Execer {
	if s.proofPackExecer != nil {
		return s.proofPackExecer
	}
	if s.manager == nil {
		return nil
	}
	return s.manager
}

// sealSubmitProofPack generates the run's pack from the workspace whose HEAD
// was just bundled, seals it, and returns the file to commit with it.
func (s *ContainerServer) sealSubmitProofPack(ctx context.Context, username, runID string, info runlease.Info, headSHA string) (*pb.SealedProofPack, submit.File, error) {
	if s.auditStore == nil {
		return nil, submit.File{}, status.Error(codes.Unavailable, "audit store not configured on this daemon: a change cannot be submitted without sealing its proof pack")
	}
	ex := s.proofPackExecerForSubmit()
	if ex == nil {
		return nil, submit.File{}, status.Error(codes.Unavailable, "container manager not configured on this daemon")
	}
	pack, err := proofpack.Generate(ctx, ex, info.Box, proofpack.Options{RepoDir: info.Workspace})
	if err != nil {
		return nil, submit.File{}, status.Errorf(codes.FailedPrecondition, "generate proof pack: %v", err)
	}
	if pack.GetGitCommit() != headSHA {
		return nil, submit.File{}, status.Errorf(codes.FailedPrecondition,
			"proof pack ran at commit %q but the submitted head is %s: the workspace moved", pack.GetGitCommit(), headSHA)
	}
	sealed, err := proofpack.Seal(ctx, s.auditStore, username, runID, pack)
	if err != nil {
		return nil, submit.File{}, status.Errorf(codes.Internal, "seal proof pack: %v", err)
	}
	body, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(sealed)
	if err != nil {
		return nil, submit.File{}, status.Errorf(codes.Internal, "encode proof pack: %v", err)
	}
	return sealed, submit.File{Path: proofpack.AttachPath, Content: append(body, '\n')}, nil
}

// proofPackDescription is the PR description's Proof Pack section.
func proofPackDescription(sealed *pb.SealedProofPack) string {
	pack := sealed.GetPack()
	return fmt.Sprintf("**Proof Pack** `sha256:%s`: %s, %d step(s), sealed at audit row %d.\n"+
		"File: `%s`. Check it on the daemon host with `containarium proof-pack verify %s`.",
		sealed.GetSeal().GetPackSha256(), proofPackStatusName(pack.GetStatus()), len(pack.GetSteps()),
		sealed.GetSeal().GetAuditRowId(), proofpack.AttachPath, proofpack.AttachPath)
}

func proofPackStatusName(st pb.ProofPackStatus) string {
	switch st {
	case pb.ProofPackStatus_PROOF_PACK_STATUS_PASSED:
		return "passed"
	case pb.ProofPackStatus_PROOF_PACK_STATUS_FAILED:
		return "failed"
	case pb.ProofPackStatus_PROOF_PACK_STATUS_NO_COMMANDS:
		return "no test commands"
	default:
		return st.String()
	}
}
