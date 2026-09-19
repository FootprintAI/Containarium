package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var _ tracker.ReaderProvider = (*Adapter)(nil)

// ghUser is the subset of GitHub's user object every response below
// needs.
type ghUser struct {
	Login string `json:"login"`
}

type ghLabel struct {
	Name string `json:"name"`
}

// ghIssue mirrors GET /repos/{owner}/{repo}/issues/{number} and the
// list endpoint's array elements. PullRequest is non-nil when this
// "issue" is actually a pull request — GitHub's issues endpoints return
// both; ListIssues filters these out so it returns issues only, GetIssue
// is never called with a PR's number by a correct caller.
type ghIssue struct {
	Number      int64     `json:"number"`
	Title       string    `json:"title"`
	Body        string    `json:"body"`
	State       string    `json:"state"`
	Labels      []ghLabel `json:"labels"`
	Assignee    *ghUser   `json:"assignee"`
	PullRequest *ghPRStub `json:"pull_request"`
}

// ghPRStub's presence (not its contents) is the signal GetIssue/ListIssues need.
type ghPRStub struct{}

type ghComment struct {
	User      ghUser `json:"user"`
	CreatedAt string `json:"created_at"`
	Body      string `json:"body"`
}

// ghPull mirrors GET /repos/{owner}/{repo}/pulls/{number}.
type ghPull struct {
	Number  int64  `json:"number"`
	State   string `json:"state"`
	Merged  bool   `json:"merged"`
	HTMLURL string `json:"html_url"`
	Head    struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

// ghCombinedStatus mirrors GET /repos/{owner}/{repo}/commits/{ref}/status.
type ghCombinedStatus struct {
	State      string `json:"state"`
	TotalCount int    `json:"total_count"`
}

// GetIssue reads a single issue and its comments (two API calls: the
// issue itself, then its comments — GitHub has no single endpoint that
// returns both).
func (a *Adapter) GetIssue(ctx context.Context, conn tracker.Conn, number int64) (tracker.Issue, error) {
	base := apiBase(conn.BaseURL)

	var raw ghIssue
	if err := a.get(ctx, fmt.Sprintf("%s/repos/%s/issues/%d", base, conn.Project, number), conn.Credential, &raw); err != nil {
		return tracker.Issue{}, err
	}

	var comments []ghComment
	if err := a.get(ctx, fmt.Sprintf("%s/repos/%s/issues/%d/comments", base, conn.Project, number), conn.Credential, &comments); err != nil {
		return tracker.Issue{}, fmt.Errorf("list comments: %w", err)
	}

	return toIssue(raw, comments), nil
}

// ListIssues enumerates issues. Search text routes through GitHub's
// Search API (a different endpoint and response shape from the plain
// list); everything else uses the ordinary issues-list endpoint.
// Either way, entries with a non-nil PullRequest are dropped — GitHub's
// issues endpoints return pull requests too, and ListTrackerIssues must
// return issues only.
func (a *Adapter) ListIssues(ctx context.Context, conn tracker.Conn, f tracker.IssueFilter) ([]tracker.Issue, error) {
	base := apiBase(conn.BaseURL)

	if f.Search != "" {
		return a.searchIssues(ctx, base, conn, f)
	}

	q := url.Values{}
	switch f.State {
	case pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN:
		q.Set("state", "open")
	case pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED:
		q.Set("state", "closed")
	default:
		q.Set("state", "all")
	}
	if len(f.Labels) > 0 {
		q.Set("labels", strings.Join(f.Labels, ","))
	}
	q.Set("per_page", "100")

	var raw []ghIssue
	if err := a.get(ctx, fmt.Sprintf("%s/repos/%s/issues?%s", base, conn.Project, q.Encode()), conn.Credential, &raw); err != nil {
		return nil, err
	}
	return toIssues(raw), nil
}

// searchIssues uses GitHub's Search API (GET /search/issues), the only
// GitHub endpoint that supports free-text search over issue title/body.
// Its response shape ({total_count, items: [...]}) differs from the
// plain list endpoint's bare array.
func (a *Adapter) searchIssues(ctx context.Context, base string, conn tracker.Conn, f tracker.IssueFilter) ([]tracker.Issue, error) {
	query := fmt.Sprintf("repo:%s is:issue %s", conn.Project, f.Search)
	switch f.State {
	case pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN:
		query += " is:open"
	case pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED:
		query += " is:closed"
	}
	for _, l := range f.Labels {
		query += fmt.Sprintf(" label:%q", l)
	}

	q := url.Values{}
	q.Set("q", query)
	q.Set("per_page", "100")

	var result struct {
		Items []ghIssue `json:"items"`
	}
	if err := a.get(ctx, fmt.Sprintf("%s/search/issues?%s", base, q.Encode()), conn.Credential, &result); err != nil {
		return nil, err
	}
	return toIssues(result.Items), nil
}

// GetChange reads a pull request's state and normalized CI verdict (two
// API calls: the PR itself for state/URL/head SHA, then the head
// commit's combined status for CI).
func (a *Adapter) GetChange(ctx context.Context, conn tracker.Conn, number int64) (tracker.Change, error) {
	base := apiBase(conn.BaseURL)

	var pr ghPull
	if err := a.get(ctx, fmt.Sprintf("%s/repos/%s/pulls/%d", base, conn.Project, number), conn.Credential, &pr); err != nil {
		return tracker.Change{}, err
	}

	var status ghCombinedStatus
	verdict := pb.TrackerCiVerdict_TRACKER_CI_VERDICT_NONE
	if pr.Head.SHA != "" {
		if err := a.get(ctx, fmt.Sprintf("%s/repos/%s/commits/%s/status", base, conn.Project, pr.Head.SHA), conn.Credential, &status); err == nil {
			verdict = combinedStatusToVerdict(status)
		}
		// A failed status lookup doesn't fail GetChange — the PR's own
		// state is still valid information; verdict just stays NONE.
	}

	return tracker.Change{
		Number:    pr.Number,
		State:     pullStateToTracker(pr),
		CIVerdict: verdict,
		URL:       pr.HTMLURL,
	}, nil
}

func pullStateToTracker(pr ghPull) pb.TrackerIssueState {
	switch {
	case pr.Merged:
		return pb.TrackerIssueState_TRACKER_ISSUE_STATE_MERGED
	case pr.State == "closed":
		return pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED
	case pr.State == "open":
		return pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN
	default:
		return pb.TrackerIssueState_TRACKER_ISSUE_STATE_UNSPECIFIED
	}
}

func combinedStatusToVerdict(s ghCombinedStatus) pb.TrackerCiVerdict {
	if s.TotalCount == 0 {
		return pb.TrackerCiVerdict_TRACKER_CI_VERDICT_NONE
	}
	switch s.State {
	case "success":
		return pb.TrackerCiVerdict_TRACKER_CI_VERDICT_SUCCESS
	case "pending":
		return pb.TrackerCiVerdict_TRACKER_CI_VERDICT_PENDING
	case "failure", "error":
		return pb.TrackerCiVerdict_TRACKER_CI_VERDICT_FAILED
	default:
		return pb.TrackerCiVerdict_TRACKER_CI_VERDICT_NONE
	}
}

func toIssues(raw []ghIssue) []tracker.Issue {
	out := make([]tracker.Issue, 0, len(raw))
	for _, r := range raw {
		if r.PullRequest != nil {
			continue // this "issue" is a pull request; ListIssues returns issues only
		}
		out = append(out, toIssue(r, nil))
	}
	return out
}

func toIssue(raw ghIssue, comments []ghComment) tracker.Issue {
	labels := make([]string, 0, len(raw.Labels))
	for _, l := range raw.Labels {
		labels = append(labels, l.Name)
	}
	assignee := ""
	if raw.Assignee != nil {
		assignee = raw.Assignee.Login
	}
	var out []tracker.Comment
	for _, c := range comments {
		out = append(out, tracker.Comment{
			Author:    c.User.Login,
			CreatedAt: parseGitHubTime(c.CreatedAt),
			Body:      c.Body,
		})
	}
	state := pb.TrackerIssueState_TRACKER_ISSUE_STATE_UNSPECIFIED
	switch raw.State {
	case "open":
		state = pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN
	case "closed":
		state = pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED
	}
	return tracker.Issue{
		Number:   raw.Number,
		Title:    raw.Title,
		Body:     raw.Body,
		State:    state,
		Labels:   labels,
		Assignee: assignee,
		Comments: out,
	}
}

// apiBase normalizes Conn.BaseURL the same way DescribeCredential does.
func apiBase(baseURL string) string {
	base := strings.TrimRight(baseURL, "/")
	if base == "" {
		base = defaultAPIBase
	}
	return base
}

// get is a GET-and-decode convenience over do, kept as its own name at
// every existing call site above.
func (a *Adapter) get(ctx context.Context, rawURL, token string, out interface{}) error {
	return a.do(ctx, http.MethodGet, rawURL, token, nil, out)
}

// do is the shared request-and-decode path for every verb — separate
// from describeViaUser/probeRateLimit (#1921) to avoid touching
// already-reviewed code for an unrelated change. reqBody is
// JSON-encoded when non-nil; out is JSON-decoded when the call
// succeeds and out is non-nil (a 204 No Content response, or a caller
// uninterested in the body, both pass out=nil).
func (a *Adapter) do(ctx context.Context, method, rawURL, token string, reqBody, out interface{}) error {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	setHeaders(req, token)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", tracker.ErrUnreachable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		if out == nil {
			return nil
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%w: HTTP %d: %s", tracker.ErrCredentialInvalid, resp.StatusCode, string(respBody))
	case http.StatusNotFound:
		return fmt.Errorf("%w: %s", tracker.ErrNotFound, rawURL)
	default:
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("github: HTTP %d: %s", resp.StatusCode, string(respBody))
	}
}

// parseGitHubTime parses GitHub's RFC3339 timestamps, returning the zero
// time on a malformed value rather than failing the whole response —
// this is a display field, not a validity signal.
func parseGitHubTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return parsed
}
