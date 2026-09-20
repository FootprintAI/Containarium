package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/tracker"
	"github.com/footprintai/containarium/internal/tracker/submit"
	"github.com/footprintai/containarium/pkg/core/container"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// *container.Manager needs no adapter to satisfy submit.BoxRunner: its
// ExecWithOutput/ReadFile methods (the same ones FetchGitSource already
// uses) already match the interface exactly.
var _ submit.BoxRunner = (*container.Manager)(nil)

// trackerFullProviderFor resolves provider to the complete
// tracker.Provider — the same resolution trackerWriterFor uses, widened
// by one more type assertion since SubmitTrackerChange is the one
// caller that needs OpenChange.
func (s *ContainerServer) trackerFullProviderFor(provider pb.TrackerProvider) (tracker.Provider, error) {
	rp, err := s.trackerProviderFor(provider)
	if err != nil {
		return nil, err
	}
	fp, ok := rp.(tracker.Provider)
	if !ok {
		return nil, fmt.Errorf("provider %v does not support submitting a change", provider)
	}
	return fp, nil
}

// remoteURLFor builds the plain (no embedded credential) HTTPS clone
// URL for a connection. No credential belongs here: GitPusher's
// hardened environment (#1951) attaches the Authorization header to
// every git invocation itself, regardless of what URL it's pushing to
// — embedding one here too would just be a second place for it to leak
// from.
func remoteURLFor(provider pb.TrackerProvider, baseURL, project string) string {
	base := strings.TrimSuffix(baseURL, "/")
	if base == "" {
		switch provider {
		case pb.TrackerProvider_TRACKER_PROVIDER_GITHUB:
			base = "https://github.com"
		case pb.TrackerProvider_TRACKER_PROVIDER_GITLAB:
			base = "https://gitlab.com"
		}
	}
	return base + "/" + project + ".git"
}

// resolveSubmitConn is resolveWriterConn's OpenChange-capable
// counterpart: same resolution (connection binding, store lookup,
// broker credential), additionally returning the full tracker.Provider
// and the push-target remote URL built from the SAME connection record
// — never from the bundle or the box, per the design note.
func (s *ContainerServer) resolveSubmitConn(ctx context.Context, username, connectionName string) (tracker.Provider, tracker.Conn, string, error) {
	if err := enforceConnectionBinding(ctx, connectionName); err != nil {
		return nil, tracker.Conn{}, "", err
	}
	trackerConn, err := s.trackerStore.Get(ctx, username, connectionName)
	if err != nil {
		return nil, tracker.Conn{}, "", mapTrackerError(err)
	}
	provider, err := s.trackerFullProviderFor(trackerConn.Provider)
	if err != nil {
		return nil, tracker.Conn{}, "", status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	if s.secretsStore == nil {
		return nil, tracker.Conn{}, "", status.Error(codes.Unavailable, "secrets store not configured on this daemon")
	}
	cred, err := s.secretsStore.BrokerCredential(ctx, username, trackerConn.CredentialSecret)
	if err != nil {
		return nil, tracker.Conn{}, "", status.Errorf(codes.FailedPrecondition, "resolve broker credential: %v", err)
	}
	remoteURL := remoteURLFor(trackerConn.Provider, trackerConn.BaseURL, trackerConn.Project)
	return provider, tracker.Conn{
		BaseURL:    trackerConn.BaseURL,
		Project:    trackerConn.Project,
		Credential: cred,
	}, remoteURL, nil
}

// boxRunnerForSubmit returns the BoxRunner SubmitTrackerChange should
// use: submitBoxRunner if a test set one, otherwise s.manager — which
// already satisfies submit.BoxRunner — or nil if neither is configured.
// A nil *container.Manager must never be returned as a non-nil
// submit.BoxRunner: a typed-nil interface would panic the first time
// ExtractBundle called a method on it, instead of surfacing Unavailable
// the way every other "store not configured" check here does.
func (s *ContainerServer) boxRunnerForSubmit() submit.BoxRunner {
	if s.submitBoxRunner != nil {
		return s.submitBoxRunner
	}
	if s.manager == nil {
		return nil
	}
	return s.manager
}

// gitPusherForSubmit returns the GitPusher SubmitTrackerChange should
// use: submitPusher if a test set one, otherwise a real
// submit.NewGitPusher() — cheap to construct per call, no shared state,
// same "construct on demand" idiom container_server.go already uses
// for the read-verb provider adapters.
func (s *ContainerServer) gitPusherForSubmit() submit.GitPusher {
	if s.submitPusher != nil {
		return s.submitPusher
	}
	return submit.NewGitPusher()
}

// baseBranchFor resolves the branch a submitted change should target.
// The run's original requested ref (runlease.Info.GitRef) is used
// as-is when set — in the overwhelming common case an agent's box is
// seeded from the branch changes should land on. Empty GitRef means
// the run fetched the remote's default branch (FetchGitSource's own
// convention for an empty ref) without recording its name; this falls
// back to "main".
//
// Known limitation, flagged rather than silently wrong: a repository
// whose default branch is named something other than "main" (e.g.
// "master", or a renamed default) gets an incorrect target when GitRef
// was empty. Resolving the provider's actual default branch would need
// a new Provider method neither adapter has today; tracked as a
// follow-up rather than blocking this PR on it.
func baseBranchFor(gitRef string) string {
	if gitRef != "" {
		return gitRef
	}
	return "main"
}

// submitChangeAuditDetail is SubmitTrackerChange's audit payload —
// same shape convention as trackerCommentAuditDetail, plus the fields
// specific to a submission: the commit range and the branch it landed
// on, so an operator reading the audit log can see exactly what was
// pushed without needing the change request itself.
type submitChangeAuditDetail struct {
	Connection  string `json:"connection"`
	Issue       int64  `json:"issue"`
	RunID       string `json:"run_id"`
	SkillID     string `json:"skill_id,omitempty"`
	BaseSHA     string `json:"base_sha"`
	HeadSHA     string `json:"head_sha"`
	Branch      string `json:"branch"`
	ChangeURL   string `json:"change_url,omitempty"`
	ChangeState string `json:"change_state,omitempty"`
}

// SubmitTrackerChange bundles the calling run's committed workspace out
// of its box, pushes it from a fresh temporary bare repository on the
// host (never a credential inside the box — see
// internal/tracker/submit), and opens a change request referencing
// req.Issue. See docs/architecture/agent-tracker-broker.md's "Submit
// path".
func (s *ContainerServer) SubmitTrackerChange(ctx context.Context, req *pb.SubmitTrackerChangeRequest) (*pb.SubmitTrackerChangeResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrackerWrite); err != nil {
		return nil, err
	}
	if s.trackerStore == nil {
		return nil, status.Error(codes.Unavailable, "tracker store not configured on this daemon")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}
	if req.Issue <= 0 {
		return nil, status.Error(codes.InvalidArgument, "issue is required")
	}
	if req.Title == "" {
		return nil, status.Error(codes.InvalidArgument, "title is required")
	}

	provider, conn, remoteURL, err := s.resolveSubmitConn(ctx, req.Username, req.Connection)
	if err != nil {
		return nil, err
	}

	// A submit needs a box to bundle from, which only a run-scoped
	// token has — an operator token (no run_id claim) has nowhere to
	// bundle a workspace out of, unlike the read/comment/claim/label
	// verbs, which work from an operator's own authenticated identity.
	runID, hasRun := auth.RunIDFromGRPCContext(ctx)
	if !hasRun || runID == "" {
		return nil, status.Error(codes.FailedPrecondition, "submitting a change requires a run-scoped token")
	}
	if s.runRegistry == nil {
		return nil, status.Error(codes.FailedPrecondition, "run registry not configured on this daemon")
	}
	info, ok := s.runRegistry.Get(runID)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "run not found or already ended")
	}
	if info.GitCommit == "" || info.Workspace == "" || info.Box == "" {
		return nil, status.Error(codes.FailedPrecondition, "run has no recorded git_source to submit from")
	}

	boxRunner := s.boxRunnerForSubmit()
	if boxRunner == nil {
		return nil, status.Error(codes.Unavailable, "container manager not configured on this daemon")
	}

	if _, err := submit.CheckHostGit(); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}

	bundle, err := submit.ExtractBundle(boxRunner, info.Box, info.Workspace, info.GitCommit, submit.DefaultMaxBundleBytes)
	if err != nil {
		if errors.Is(err, submit.ErrBundleTooLarge) || errors.Is(err, submit.ErrBundleMalformed) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "extract bundle: %v", err)
	}
	defer func() { _ = os.Remove(bundle.BundlePath) }()

	id := s.identityFromContext(ctx)
	closingRef := fmt.Sprintf("Closes #%d", req.Issue)
	description := tracker.Sanitize(req.Description)
	fullDescription := closingRef + "\n\n" + description + "\n\n" + tracker.Stamp(id, tracker.KindChange)

	pushResult, err := s.gitPusherForSubmit().PushBundle(ctx, submit.PushSpec{
		BundlePath:  bundle.BundlePath,
		BaseSHA:     info.GitCommit,
		HeadSHA:     bundle.HeadSHA,
		RemoteURL:   remoteURL,
		Credential:  conn.Credential,
		RunID:       runID,
		IssueNumber: req.Issue,
		Title:       req.Title,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "push bundle: %v", err)
	}

	change, err := provider.OpenChange(ctx, conn, tracker.OpenChangeRequest{
		HeadBranch:  pushResult.Branch,
		BaseBranch:  baseBranchFor(info.GitRef),
		Title:       req.Title,
		Description: fullDescription,
		Draft:       req.Draft,
	})
	if err != nil {
		return nil, mapProviderError(err)
	}

	s.auditTrackerWrite(ctx, "tracker.submit_change", req.Username, req.Connection, req.Issue, submitChangeAuditDetail{
		Connection:  req.Connection,
		Issue:       req.Issue,
		RunID:       runID,
		SkillID:     id.SkillID,
		BaseSHA:     info.GitCommit,
		HeadSHA:     pushResult.SHA,
		Branch:      pushResult.Branch,
		ChangeURL:   change.URL,
		ChangeState: change.State.String(),
	})

	return &pb.SubmitTrackerChangeResponse{Change: toProtoChange(change)}, nil
}
