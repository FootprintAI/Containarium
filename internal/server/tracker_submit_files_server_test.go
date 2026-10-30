package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/tracker"
	"github.com/footprintai/containarium/internal/tracker/submit"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeFilePusher is a submit.FilePusher test double recording the
// FilesSpec it was called with.
type fakeFilePusher struct {
	called  bool
	gotSpec submit.FilesSpec
	result  submit.PushResult
	err     error
}

func (f *fakeFilePusher) PushFiles(_ context.Context, spec submit.FilesSpec) (submit.PushResult, error) {
	f.called = true
	f.gotSpec = spec
	return f.result, f.err
}

func validFilesReq(user string) *pb.SubmitTrackerChangeFilesRequest {
	return &pb.SubmitTrackerChangeFilesRequest{
		Username: user, Connection: "default", Issue: 7, Title: "Fix the thing",
		Files: []*pb.TrackerChangeFile{{Path: "docs/a.md", Content: "hello\n"}},
	}
}

// setUpFilesConnection is setUpWriterConnection with an OPERATOR context
// (tracker:write, no run_id claim) — the caller this RPC exists for —
// and the file pusher swapped for a fake.
func setUpFilesConnection(t *testing.T, user string, provider *fakeWriterProvider, pusher *fakeFilePusher) (*ContainerServer, context.Context) {
	t.Helper()
	s, _ := setUpWriterConnection(t, user, provider)
	s.submitFilePusher = pusher
	return s, kmsKeyTestCtx(user, "member", "tracker:write")
}

func TestSubmitTrackerChangeFiles_AuthAndArgs(t *testing.T) {
	tests := []struct {
		name string
		s    *ContainerServer
		ctx  context.Context
		mut  func(*pb.SubmitTrackerChangeFilesRequest)
		want codes.Code
	}{
		{"no auth", &ContainerServer{}, context.Background(), nil, codes.Unauthenticated},
		{"read scope", &ContainerServer{}, kmsKeyTestCtx("alice", "member", "tracker:read"), nil, codes.PermissionDenied},
		{"no tracker store", &ContainerServer{}, kmsKeyTestCtx("alice", "member", "tracker:write"), nil, codes.Unavailable},
		{"cross tenant", &ContainerServer{trackerStore: mustTestTrackerStore(t)}, kmsKeyTestCtx("mallory", "member", "tracker:write"), nil, codes.PermissionDenied},
		{"missing issue", &ContainerServer{trackerStore: mustTestTrackerStore(t)}, kmsKeyTestCtx("alice", "member", "tracker:write"),
			func(r *pb.SubmitTrackerChangeFilesRequest) { r.Issue = 0 }, codes.InvalidArgument},
		{"missing title", &ContainerServer{trackerStore: mustTestTrackerStore(t)}, kmsKeyTestCtx("alice", "member", "tracker:write"),
			func(r *pb.SubmitTrackerChangeFilesRequest) { r.Title = "" }, codes.InvalidArgument},
		{"no files", &ContainerServer{trackerStore: mustTestTrackerStore(t)}, kmsKeyTestCtx("alice", "member", "tracker:write"),
			func(r *pb.SubmitTrackerChangeFilesRequest) { r.Files = nil }, codes.InvalidArgument},
		{"bad path", &ContainerServer{trackerStore: mustTestTrackerStore(t)}, kmsKeyTestCtx("alice", "member", "tracker:write"),
			func(r *pb.SubmitTrackerChangeFilesRequest) { r.Files[0].Path = "../escape" }, codes.InvalidArgument},
		{"over size cap", &ContainerServer{trackerStore: mustTestTrackerStore(t)}, kmsKeyTestCtx("alice", "member", "tracker:write"),
			func(r *pb.SubmitTrackerChangeFilesRequest) {
				r.Files[0].Content = strings.Repeat("x", submit.DefaultMaxChangeFilesBytes+1)
			}, codes.InvalidArgument},
		{"bad head branch", &ContainerServer{trackerStore: mustTestTrackerStore(t)}, kmsKeyTestCtx("alice", "member", "tracker:write"),
			func(r *pb.SubmitTrackerChangeFilesRequest) { r.HeadBranch = "a..b" }, codes.InvalidArgument},
		{"bad base ref", &ContainerServer{trackerStore: mustTestTrackerStore(t)}, kmsKeyTestCtx("alice", "member", "tracker:write"),
			func(r *pb.SubmitTrackerChangeFilesRequest) { r.BaseRef = "-x" }, codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validFilesReq("alice")
			if tt.mut != nil {
				tt.mut(req)
			}
			_, err := tt.s.SubmitTrackerChangeFiles(tt.ctx, req)
			if status.Code(err) != tt.want {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tt.want)
			}
		})
	}
}

func TestSubmitTrackerChangeFiles_HeadEqualsBaseRefused(t *testing.T) {
	const user = "tracker-rpc-files-head-is-base"
	pusher := &fakeFilePusher{}
	s, ctx := setUpFilesConnection(t, user, &fakeWriterProvider{defaultBranchOut: "trunk"}, pusher)
	req := validFilesReq(user)
	req.HeadBranch = "trunk"
	_, err := s.SubmitTrackerChangeFiles(ctx, req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (head branch is the base branch)", status.Code(err))
	}
	if pusher.called {
		t.Error("pusher called for a head branch equal to the base")
	}
}

func TestSubmitTrackerChangeFiles_PushFails(t *testing.T) {
	const user = "tracker-rpc-files-push-fails"
	provider := &fakeWriterProvider{}
	s, ctx := setUpFilesConnection(t, user, provider, &fakeFilePusher{err: errors.New("push rejected")})
	_, err := s.SubmitTrackerChangeFiles(ctx, validFilesReq(user))
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal (push failure)", status.Code(err))
	}
	if provider.openChangeReq.HeadBranch != "" {
		t.Error("OpenChange called after a failed push")
	}
}

func TestSubmitTrackerChangeFiles_DefaultBranchFails(t *testing.T) {
	const user = "tracker-rpc-files-default-branch-fails"
	pusher := &fakeFilePusher{}
	s, ctx := setUpFilesConnection(t, user, &fakeWriterProvider{defaultBranchErr: tracker.ErrUnreachable}, pusher)
	_, err := s.SubmitTrackerChangeFiles(ctx, validFilesReq(user))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
	if pusher.called {
		t.Error("pushed without a resolved base branch")
	}
}

func TestSubmitTrackerChangeFiles_OpenChangeFails(t *testing.T) {
	const user = "tracker-rpc-files-openchange-fails"
	provider := &fakeWriterProvider{openChangeErr: tracker.ErrCredentialInvalid}
	pusher := &fakeFilePusher{result: submit.PushResult{Branch: "containarium/issue-7", SHA: "abc"}}
	s, ctx := setUpFilesConnection(t, user, provider, pusher)
	_, err := s.SubmitTrackerChangeFiles(ctx, validFilesReq(user))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (credential rejected)", status.Code(err))
	}
}

// TestSubmitTrackerChangeFiles_HappyPath: an operator token with no run
// and no run registry opens a change from files — the pusher gets the
// files, the resolved default branch, the daemon-chosen head branch and
// the broker credential; OpenChange gets the pushed branch and the
// stamped description; the write is audited.
func TestSubmitTrackerChangeFiles_HappyPath(t *testing.T) {
	user := "tracker-rpc-files-happy-" + uuid.NewString()
	provider := &fakeWriterProvider{
		defaultBranchOut: "trunk",
		openChangeOut:    tracker.Change{Number: 9, URL: "https://github.com/acme/widgets/pull/9"},
	}
	wantHead := submit.FilesBranchName(user, "default", 7, "Fix the thing")
	pusher := &fakeFilePusher{result: submit.PushResult{Branch: wantHead, SHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
	s, ctx := setUpFilesConnection(t, user, provider, pusher)
	s.auditStore = mustTestAuditStore(t)

	req := validFilesReq(user)
	req.Description = "does the thing"
	req.Draft = true
	resp, err := s.SubmitTrackerChangeFiles(ctx, req)
	if err != nil {
		t.Fatalf("SubmitTrackerChangeFiles: %v", err)
	}
	if resp.GetChange().GetNumber() != 9 || resp.GetChange().GetUrl() != "https://github.com/acme/widgets/pull/9" {
		t.Errorf("response change = %v, want #9 with the provider's URL", resp.GetChange())
	}

	got := pusher.gotSpec
	if got.BaseBranch != "trunk" || got.HeadBranch != wantHead {
		t.Errorf("FilesSpec base/head = %q/%q, want trunk/%q", got.BaseBranch, got.HeadBranch, wantHead)
	}
	if len(got.Files) != 1 || got.Files[0] != (submit.ChangeFile{Path: "docs/a.md", Content: "hello\n"}) {
		t.Errorf("FilesSpec.Files = %+v, want the request's file", got.Files)
	}
	if got.Credential == "" || got.RemoteURL != "https://github.com/acme/widgets.git" {
		t.Errorf("FilesSpec credential set=%v remote=%q, want the connection's broker credential and remote", got.Credential != "", got.RemoteURL)
	}
	if !strings.HasPrefix(got.Message, "Fix the thing\n\n") || !strings.Contains(got.Message, "via Containarium") {
		t.Errorf("commit message = %q, want title + platform stamp", got.Message)
	}

	oc := provider.openChangeReq
	if oc.HeadBranch != wantHead || oc.BaseBranch != "trunk" || !oc.Draft || oc.Title != "Fix the thing" {
		t.Errorf("OpenChangeRequest = %+v, want pushed head, trunk base, draft, title", oc)
	}
	for _, want := range []string{"Closes #7", "does the thing", "via Containarium", "kind=change"} {
		if !strings.Contains(oc.Description, want) {
			t.Errorf("OpenChangeRequest.Description = %q, want it to contain %q", oc.Description, want)
		}
	}

	rows, _, err := s.auditStore.Query(context.Background(), audit.QueryParams{Username: user, Action: "tracker.submit_change_files", Limit: 10})
	if err != nil {
		t.Fatalf("audit Query: %v", err)
	}
	if len(rows) != 1 || !strings.Contains(rows[0].Detail, wantHead) || rows[0].RunID != "" {
		t.Errorf("audit rows = %+v, want one tracker.submit_change_files row naming the branch, no run id", rows)
	}
}

// TestSubmitTrackerChangeFiles_ExplicitRefs: base_ref and head_branch
// are used as given; the provider's default branch is not consulted.
func TestSubmitTrackerChangeFiles_ExplicitRefs(t *testing.T) {
	const user = "tracker-rpc-files-explicit-refs"
	provider := &fakeWriterProvider{defaultBranchErr: tracker.ErrUnreachable, openChangeOut: tracker.Change{Number: 1}}
	pusher := &fakeFilePusher{result: submit.PushResult{Branch: "containarium/issue-7", SHA: "abc"}}
	s, ctx := setUpFilesConnection(t, user, provider, pusher)
	req := validFilesReq(user)
	req.BaseRef, req.HeadBranch = "release/1.2", "containarium/issue-7"
	if _, err := s.SubmitTrackerChangeFiles(ctx, req); err != nil {
		t.Fatalf("SubmitTrackerChangeFiles: %v", err)
	}
	if pusher.gotSpec.BaseBranch != "release/1.2" || pusher.gotSpec.HeadBranch != "containarium/issue-7" {
		t.Errorf("FilesSpec base/head = %q/%q", pusher.gotSpec.BaseBranch, pusher.gotSpec.HeadBranch)
	}
	if provider.openChangeReq.BaseBranch != "release/1.2" {
		t.Errorf("OpenChange base = %q, want release/1.2", provider.openChangeReq.BaseBranch)
	}
}

// #3288: a head branch that already has an open change request reuses it
// — no second OpenChange — and the response is that change, so a second
// call for the same head_branch returns the same change.
func TestSubmitTrackerChangeFiles_ReusesOpenChange(t *testing.T) {
	user := "tracker-rpc-files-reuse-" + uuid.NewString()
	existing := tracker.Change{Number: 5, URL: "https://gitlab.example/acme/widgets/-/merge_requests/5",
		State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN, Branch: "containarium/issue-7"}
	provider := &fakeWriterProvider{findOpenOut: existing, findOpenFound: true, openChangeErr: errors.New("must not open a second change")}
	pusher := &fakeFilePusher{result: submit.PushResult{Branch: "containarium/issue-7", SHA: "cccccccccccccccccccccccccccccccccccccccc"}}
	s, ctx := setUpFilesConnection(t, user, provider, pusher)
	s.auditStore = mustTestAuditStore(t)
	req := validFilesReq(user)
	req.HeadBranch = "containarium/issue-7"

	resp, err := s.SubmitTrackerChangeFiles(ctx, req)
	if err != nil {
		t.Fatalf("SubmitTrackerChangeFiles: %v", err)
	}
	if provider.findOpenBranch != "containarium/issue-7" {
		t.Errorf("FindOpenChange asked about %q, want the pushed head branch", provider.findOpenBranch)
	}
	if provider.openChangeReq.HeadBranch != "" {
		t.Errorf("OpenChange called (%+v) although an open change exists for the branch", provider.openChangeReq)
	}
	if got := resp.GetChange(); got.GetNumber() != 5 || got.GetUrl() != existing.URL || got.GetBranch() != "containarium/issue-7" {
		t.Errorf("response change = %v, want the existing !5", got)
	}
	rows, _, err := s.auditStore.Query(context.Background(), audit.QueryParams{Username: user, Action: "tracker.submit_change_files", Limit: 10})
	if err != nil {
		t.Fatalf("audit Query: %v", err)
	}
	if len(rows) != 1 || !strings.Contains(rows[0].Detail, existing.URL) || !strings.Contains(rows[0].Detail, `"reused_change":true`) {
		t.Errorf("audit rows = %+v, want one row naming the reused change", rows)
	}
}

// #3288: an existing branch whose earlier change was merged or closed has
// no open change, so a new one is opened (documented behaviour).
func TestSubmitTrackerChangeFiles_NoOpenChangeOpensNew(t *testing.T) {
	const user = "tracker-rpc-files-no-open-change"
	provider := &fakeWriterProvider{openChangeOut: tracker.Change{Number: 6}}
	pusher := &fakeFilePusher{result: submit.PushResult{Branch: "containarium/issue-7", SHA: "abc"}}
	s, ctx := setUpFilesConnection(t, user, provider, pusher)
	req := validFilesReq(user)
	req.HeadBranch = "containarium/issue-7"
	resp, err := s.SubmitTrackerChangeFiles(ctx, req)
	if err != nil {
		t.Fatalf("SubmitTrackerChangeFiles: %v", err)
	}
	if provider.findOpenBranch != "containarium/issue-7" {
		t.Errorf("FindOpenChange asked about %q", provider.findOpenBranch)
	}
	if provider.openChangeReq.HeadBranch != "containarium/issue-7" || resp.GetChange().GetNumber() != 6 {
		t.Errorf("OpenChange req %+v / response %v, want a new change opened", provider.openChangeReq, resp.GetChange())
	}
}

// #3288: a failed lookup fails the call rather than risking a duplicate.
func TestSubmitTrackerChangeFiles_FindOpenChangeFails(t *testing.T) {
	const user = "tracker-rpc-files-find-open-fails"
	provider := &fakeWriterProvider{findOpenErr: tracker.ErrUnreachable}
	pusher := &fakeFilePusher{result: submit.PushResult{Branch: "containarium/issue-7", SHA: "abc"}}
	s, ctx := setUpFilesConnection(t, user, provider, pusher)
	_, err := s.SubmitTrackerChangeFiles(ctx, validFilesReq(user))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", status.Code(err), err)
	}
	if provider.openChangeReq.HeadBranch != "" {
		t.Error("OpenChange called after the open-change lookup failed")
	}
}

// #3288: a head branch that moved under the push is Aborted with the
// pusher's explanation, and no change is opened or looked up.
func TestSubmitTrackerChangeFiles_HeadMovedIsAborted(t *testing.T) {
	const user = "tracker-rpc-files-head-moved"
	provider := &fakeWriterProvider{}
	pusher := &fakeFilePusher{err: fmt.Errorf("%w: \"containarium/issue-7\" is now at abc", submit.ErrHeadBranchMoved)}
	s, ctx := setUpFilesConnection(t, user, provider, pusher)
	_, err := s.SubmitTrackerChangeFiles(ctx, validFilesReq(user))
	if status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), "moved") {
		t.Fatalf("err = %v, want Aborted naming the moved branch", err)
	}
	if provider.openChangeReq.HeadBranch != "" || provider.findOpenBranch != "" {
		t.Error("change opened or looked up after a refused push")
	}
}
