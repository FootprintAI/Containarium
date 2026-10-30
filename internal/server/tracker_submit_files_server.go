package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/tracker"
	"github.com/footprintai/containarium/internal/tracker/submit"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// filePusherForSubmit returns submitFilePusher if a test set one,
// otherwise a real submit.NewGitPusher().
func (s *ContainerServer) filePusherForSubmit() submit.FilePusher {
	if s.submitFilePusher != nil {
		return s.submitFilePusher
	}
	return submit.NewGitPusher()
}

// SubmitTrackerChangeFiles opens a change request from a file set over
// the connection's broker credential, with no run box (#3005): the
// files are committed in a fresh temporary repository on the host — on
// the head branch's tip when it already exists on the remote, otherwise
// on the base branch — and pushed without force, then the change is
// opened exactly as SubmitTrackerChange opens one, unless the head
// branch already has an open change, which is reused (#3288). Authorised like
// CommentOnTrackerIssue — tracker:write plus tenant authority on the
// connection — since there is no box for a run-scoped token to name.
func (s *ContainerServer) SubmitTrackerChangeFiles(ctx context.Context, req *pb.SubmitTrackerChangeFilesRequest) (*pb.SubmitTrackerChangeFilesResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrackerWrite); err != nil {
		return nil, err
	}
	if s.trackerStore == nil {
		return nil, status.Error(codes.Unavailable, "tracker store not configured on this daemon")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTrackerTenant(ctx, req.Username); err != nil {
		return nil, err
	}
	if req.Issue <= 0 {
		return nil, status.Error(codes.InvalidArgument, "issue is required")
	}
	if req.Title == "" {
		return nil, status.Error(codes.InvalidArgument, "title is required")
	}
	files := make([]submit.ChangeFile, 0, len(req.Files))
	for _, f := range req.Files {
		files = append(files, submit.ChangeFile{Path: f.GetPath(), Content: f.GetContent()})
	}
	if err := submit.ValidateChangeFiles(files, submit.DefaultMaxChangeFilesBytes); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	for _, b := range []string{req.BaseRef, req.HeadBranch} {
		if b == "" {
			continue
		}
		if err := submit.ValidateBranchName(b); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}

	provider, conn, remoteURL, err := s.resolveSubmitConn(ctx, req.Username, req.Connection)
	if err != nil {
		return nil, err
	}
	if _, err := submit.CheckHostGit(); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}

	baseBranch, err := baseBranchFor(ctx, provider, conn, req.BaseRef)
	if err != nil {
		return nil, mapProviderError(err)
	}
	if err := submit.ValidateBranchName(baseBranch); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "tracker default branch: %v", err)
	}
	headBranch := req.HeadBranch
	if headBranch == "" {
		headBranch = submit.FilesBranchName(req.Username, req.Connection, req.Issue, req.Title)
	}
	if headBranch == baseBranch {
		return nil, status.Errorf(codes.InvalidArgument, "head_branch must differ from the base branch %q", baseBranch)
	}

	id := s.identityFromContext(ctx)
	stamp := tracker.Stamp(id, tracker.KindChange)
	pushResult, err := s.filePusherForSubmit().PushFiles(ctx, submit.FilesSpec{
		RemoteURL:  remoteURL,
		Credential: conn.Credential,
		BaseBranch: baseBranch,
		HeadBranch: headBranch,
		Message:    req.Title + "\n\n" + stamp,
		Files:      files,
	})
	if err != nil {
		if errors.Is(err, submit.ErrInvalidBranch) || errors.Is(err, submit.ErrInvalidChangeFile) || errors.Is(err, submit.ErrChangeFilesTooLarge) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		if errors.Is(err, submit.ErrHeadBranchMoved) {
			return nil, status.Error(codes.Aborted, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "push files: %v", err)
	}

	// #3288: a head branch that already has an open change request gets
	// the new commit on that change rather than a second one (GitLab
	// refuses a second open MR for a source branch). A branch whose
	// earlier change was merged or closed has none open, so a new one is
	// opened.
	change, reused, err := provider.FindOpenChange(ctx, conn, pushResult.Branch)
	if err != nil {
		return nil, mapProviderError(err)
	}
	if !reused {
		fullDescription := fmt.Sprintf("Closes #%d", req.Issue) + "\n\n" + tracker.Sanitize(req.Description) + "\n\n" + stamp
		change, err = provider.OpenChange(ctx, conn, tracker.OpenChangeRequest{
			HeadBranch:  pushResult.Branch,
			BaseBranch:  baseBranch,
			Title:       req.Title,
			Description: fullDescription,
			Draft:       req.Draft,
		})
		if err != nil {
			return nil, mapProviderError(err)
		}
	}

	runID, _ := auth.RunIDFromGRPCContext(ctx)
	s.auditTrackerWrite(ctx, "tracker.submit_change_files", req.Username, req.Connection, req.Issue, submitChangeAuditDetail{
		Connection:   req.Connection,
		Issue:        req.Issue,
		RunID:        runID,
		SkillID:      id.SkillID,
		BaseSHA:      pushResult.BaseSHA,
		HeadSHA:      pushResult.SHA,
		Branch:       pushResult.Branch,
		ChangeURL:    change.URL,
		ChangeState:  change.State.String(),
		ReusedChange: reused,
	})

	return &pb.SubmitTrackerChangeFilesResponse{Change: toProtoChange(change)}, nil
}
