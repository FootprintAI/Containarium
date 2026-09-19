package tracker

import (
	"context"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Issue is the provider-neutral shape of a tracker issue — one `number`
// rather than GitHub's number vs GitLab's iid, a typed TrackerIssueState
// rather than "open"/"opened", normalized fields throughout. No
// provider-specific field name or string reaches a caller.
type Issue struct {
	Number int64
	Title  string
	Body   string
	State  pb.TrackerIssueState
	Labels []string
	// Assignee is the provider username, empty when unassigned. Single
	// value even on GitHub (which allows several) — the broker only
	// ever needs "is this claimed," and GitLab Free's single-assignee
	// model is what AssignIfUnassigned (#1922 step 5) is designed
	// around; a second GitHub assignee is invisible here by design
	// rather than by omission.
	Assignee string
	// Comments is populated only by GetIssue — ListIssues never fetches
	// them (neither provider's list endpoint includes them, and
	// fetching per-issue would be an N+1 call pattern neither
	// provider's rate limits are generous with).
	Comments []Comment
}

// Comment is one normalized issue or merge-request comment.
type Comment struct {
	Author    string
	CreatedAt time.Time
	Body      string
}

// Change is the provider-neutral shape of a GitHub pull request or
// GitLab merge request.
type Change struct {
	Number    int64
	State     pb.TrackerIssueState
	CIVerdict pb.TrackerCiVerdict
	URL       string
}

// IssueFilter narrows ListIssues. The zero value matches every issue.
type IssueFilter struct {
	// State filters by issue state; UNSPECIFIED matches any state.
	State pb.TrackerIssueState
	// Labels, when non-empty, requires ALL of these labels (both
	// providers' native list APIs support this as an AND filter).
	Labels []string
	// Search is a free-text query against title/body, passed through to
	// the provider's own search — no normalization possible across two
	// different search implementations, so treat results as
	// best-effort, not authoritative.
	Search string
}

// OpenChangeRequest is #1923's submit-path input. Declared here now so
// the full Provider interface (below) is complete and both adapters
// satisfy it from the day they exist, even though nothing calls
// OpenChange until #1923 wires the submit path that builds one.
type OpenChangeRequest struct {
	HeadBranch  string
	BaseBranch  string
	Title       string
	Description string
	Draft       bool
}

// ReaderProvider is the read half of Provider: GetIssue, ListIssues,
// GetChange, and DescribeCredential (#1921). This PR (#1922 build-order
// step 4) lands only these — both adapters implement exactly this
// interface today. The next stacked PR (step 5) adds the write verbs
// below and widens callers from ReaderProvider to the full Provider.
type ReaderProvider interface {
	CredentialDescriber
	GetIssue(ctx context.Context, c Conn, number int64) (Issue, error)
	ListIssues(ctx context.Context, c Conn, f IssueFilter) ([]Issue, error)
	GetChange(ctx context.Context, c Conn, number int64) (Change, error)
}

// WriterProvider is the write half of Provider needed by #1922's write
// verbs (CommentOnTrackerIssue, ClaimTrackerIssue, SetTrackerIssueLabels).
// OpenChange — the remaining Provider method — is #1923's submit path
// and isn't implemented by either adapter yet, so it stays out of this
// interface rather than forcing a stub.
type WriterProvider interface {
	ReaderProvider
	// Comment posts a comment and returns its normalized form.
	Comment(ctx context.Context, c Conn, number int64, body string) (Comment, error)
	// AssignIfUnassigned assigns the connection's credential's own
	// account to the issue, but only if it currently has no assignee —
	// never replaces an existing one. Returns whether it actually
	// assigned (false when already assigned by someone else, which is
	// not an error — the caller's claim logic decides what that means).
	AssignIfUnassigned(ctx context.Context, c Conn, number int64) (assigned bool, err error)
	// SetLabels adds and removes labels in one call. Allow-list
	// enforcement is the broker core's job, not the adapter's.
	SetLabels(ctx context.Context, c Conn, number int64, add, remove []string) error
}

// Provider is the full per-tracker verb set, adding OpenChange (#1923's
// submit path) to WriterProvider. Not yet satisfied by either adapter —
// lands once #1923 implements OpenChange.
type Provider interface {
	WriterProvider
	// OpenChange pushes a change request. #1923.
	OpenChange(ctx context.Context, c Conn, req OpenChangeRequest) (Change, error)
}
