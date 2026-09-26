package gitlab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var _ tracker.ReaderProvider = (*Adapter)(nil)

type glAuthor struct {
	Username string `json:"username"`
}

// glIssue mirrors GET /projects/{id}/issues/{iid}. GitLab returns labels
// as plain strings (unlike GitHub's {name: "..."} objects).
type glIssue struct {
	IID         int64     `json:"iid"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	State       string    `json:"state"`
	Labels      []string  `json:"labels"`
	Assignee    *glAuthor `json:"assignee"`
}

// glNote mirrors one element of GET /projects/{id}/issues/{iid}/notes.
// System is true for GitLab's auto-generated activity notes ("assigned
// to @x", "changed the description") — those aren't comments and are
// filtered out.
type glNote struct {
	Author    glAuthor `json:"author"`
	CreatedAt string   `json:"created_at"`
	Body      string   `json:"body"`
	System    bool     `json:"system"`
}

// glPipeline is the subset of a pipeline object GetChange needs.
type glPipeline struct {
	Status string `json:"status"`
}

// glMergeRequest mirrors GET /projects/{id}/merge_requests/{iid}.
// HeadPipeline is null when no pipeline has ever run for this MR.
type glMergeRequest struct {
	IID          int64       `json:"iid"`
	State        string      `json:"state"`
	WebURL       string      `json:"web_url"`
	HeadPipeline *glPipeline `json:"head_pipeline"`
}

// GetIssue reads a single issue and its comments (two API calls: the
// issue itself, then its notes, filtered to non-system ones).
func (a *Adapter) GetIssue(ctx context.Context, conn tracker.Conn, number int64) (tracker.Issue, error) {
	apiBase := apiBaseURL(conn.BaseURL)
	projectPath := url.PathEscape(conn.Project)

	var raw glIssue
	if err := a.get(ctx, fmt.Sprintf("%s/projects/%s/issues/%d", apiBase, projectPath, number), conn.Credential, &raw); err != nil {
		return tracker.Issue{}, err
	}

	var notes []glNote
	if err := a.get(ctx, fmt.Sprintf("%s/projects/%s/issues/%d/notes", apiBase, projectPath, number), conn.Credential, &notes); err != nil {
		return tracker.Issue{}, fmt.Errorf("list notes: %w", err)
	}

	return toIssue(raw, notes), nil
}

// ListIssues enumerates issues. state/labels/search all map directly
// onto GitLab's own list query parameters — no separate search
// endpoint needed here, unlike GitHub.
func (a *Adapter) ListIssues(ctx context.Context, conn tracker.Conn, f tracker.IssueFilter) ([]tracker.Issue, error) {
	apiBase := apiBaseURL(conn.BaseURL)
	projectPath := url.PathEscape(conn.Project)

	q := url.Values{}
	switch f.State {
	case pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN:
		q.Set("state", "opened")
	case pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED:
		q.Set("state", "closed")
		// UNSPECIFIED: omit state entirely — GitLab has no "all" state
		// value; omitting the parameter is what returns every state.
	}
	if len(f.Labels) > 0 {
		q.Set("labels", strings.Join(f.Labels, ","))
	}
	if f.Search != "" {
		q.Set("search", f.Search)
	}
	q.Set("per_page", "100")

	raw, err := getAllPages[glIssue](ctx, a, fmt.Sprintf("%s/projects/%s/issues?%s", apiBase, projectPath, q.Encode()), conn.Credential)
	if err != nil {
		return nil, err
	}
	out := make([]tracker.Issue, 0, len(raw))
	for _, r := range raw {
		out = append(out, toIssue(r, nil))
	}
	return out, nil
}

// GetChange reads a merge request's state and normalized CI verdict —
// one API call, since GitLab embeds the most recent pipeline's status
// directly on the merge request object.
func (a *Adapter) GetChange(ctx context.Context, conn tracker.Conn, number int64) (tracker.Change, error) {
	apiBase := apiBaseURL(conn.BaseURL)
	projectPath := url.PathEscape(conn.Project)

	var mr glMergeRequest
	if err := a.get(ctx, fmt.Sprintf("%s/projects/%s/merge_requests/%d", apiBase, projectPath, number), conn.Credential, &mr); err != nil {
		return tracker.Change{}, err
	}

	return tracker.Change{
		Number:    mr.IID,
		State:     mergeRequestStateToTracker(mr.State),
		CIVerdict: pipelineToVerdict(mr.HeadPipeline),
		URL:       mr.WebURL,
	}, nil
}

func mergeRequestStateToTracker(state string) pb.TrackerIssueState {
	switch state {
	case "opened":
		return pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN
	case "closed":
		return pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED
	case "merged":
		return pb.TrackerIssueState_TRACKER_ISSUE_STATE_MERGED
	default:
		return pb.TrackerIssueState_TRACKER_ISSUE_STATE_UNSPECIFIED
	}
}

// pipelineToVerdict maps GitLab's pipeline status to the normalized CI
// verdict. manual / skipped / canceled deliberately map to NONE, not
// SUCCESS — an agent deciding whether to act on "CI passed" must not be
// misled by a pipeline that never actually completed.
func pipelineToVerdict(p *glPipeline) pb.TrackerCiVerdict {
	if p == nil {
		return pb.TrackerCiVerdict_TRACKER_CI_VERDICT_NONE
	}
	switch p.Status {
	case "success":
		return pb.TrackerCiVerdict_TRACKER_CI_VERDICT_SUCCESS
	case "failed":
		return pb.TrackerCiVerdict_TRACKER_CI_VERDICT_FAILED
	case "running", "pending", "created", "waiting_for_resource", "preparing", "scheduled":
		return pb.TrackerCiVerdict_TRACKER_CI_VERDICT_PENDING
	default:
		// canceled, skipped, manual, or anything unrecognized.
		return pb.TrackerCiVerdict_TRACKER_CI_VERDICT_NONE
	}
}

func toIssue(raw glIssue, notes []glNote) tracker.Issue {
	assignee := ""
	if raw.Assignee != nil {
		assignee = raw.Assignee.Username
	}
	state := pb.TrackerIssueState_TRACKER_ISSUE_STATE_UNSPECIFIED
	switch raw.State {
	case "opened":
		state = pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN
	case "closed":
		state = pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED
	}
	var comments []tracker.Comment
	for _, n := range notes {
		if n.System {
			continue
		}
		comments = append(comments, tracker.Comment{
			Author:    n.Author.Username,
			CreatedAt: parseGitLabTime(n.CreatedAt),
			Body:      n.Body,
		})
	}
	return tracker.Issue{
		Number:   raw.IID,
		Title:    raw.Title,
		Body:     raw.Description,
		State:    state,
		Labels:   raw.Labels,
		Assignee: assignee,
		Comments: comments,
	}
}

// apiBaseURL normalizes Conn.BaseURL the same way DescribeCredential
// does. Separate function (not reused from adapter.go) to avoid
// touching already-reviewed #1921 code for an unrelated change.
func apiBaseURL(baseURL string) string {
	base := strings.TrimSuffix(baseURL, "/")
	if base == "" {
		base = defaultBaseURL
	}
	if !strings.HasSuffix(base, "/api/v4") {
		base += "/api/v4"
	}
	return base
}

// get is the shared GET-and-decode path for the read verbs.
func (a *Adapter) get(ctx context.Context, rawURL, token string, out interface{}) error {
	return a.do(ctx, http.MethodGet, rawURL, token, nil, out)
}

// do is the shared request-and-decode path for every verb. reqBody is
// JSON-encoded when non-nil; out is JSON-decoded when the call
// succeeds and out is non-nil.
func (a *Adapter) do(ctx context.Context, method, rawURL, token string, reqBody, out interface{}) error {
	_, err := a.doWithHeader(ctx, method, rawURL, token, reqBody, out)
	return err
}

// getAllPages GETs firstURL and every page its Link header chains to
// (rel="next"; GitLab sends it alongside X-Next-Page), collecting each
// page's items — the fix for #2040, where ListIssues read only the
// first page of 100. It stops after tracker.MaxListPages pages, logging
// that the result is truncated, and refuses a next link on a different
// host (the credential would follow it).
func getAllPages[T any](ctx context.Context, a *Adapter, firstURL, token string) ([]T, error) {
	var all []T
	next := firstURL
	for page := 1; next != ""; page++ {
		if page > tracker.MaxListPages {
			log.Printf("gitlab: list truncated after %d pages (%d items); more pages exist upstream", tracker.MaxListPages, len(all))
			break
		}
		var items []T
		h, err := a.doWithHeader(ctx, http.MethodGet, next, token, nil, &items)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		n := tracker.NextPageURL(h.Get("Link"))
		if n != "" {
			if err := tracker.CheckSameOrigin(next, n); err != nil {
				return nil, fmt.Errorf("gitlab: %w", err)
			}
		}
		next = n
	}
	return all, nil
}

// doWithHeader is do, also returning the response headers on success
// (pagination reads the Link header).
func (a *Adapter) doWithHeader(ctx context.Context, method, rawURL, token string, reqBody, out interface{}) (http.Header, error) {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", tracker.ErrUnreachable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		if out == nil {
			return resp.Header, nil
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
		return resp.Header, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: HTTP %d: %s", tracker.ErrCredentialInvalid, resp.StatusCode, string(respBody))
	case http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", tracker.ErrNotFound, rawURL)
	default:
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gitlab: HTTP %d: %s", resp.StatusCode, string(respBody))
	}
}

// parseGitLabTime parses GitLab's RFC3339 note timestamps, returning
// the zero time on a malformed value — a display field, not a validity
// signal.
func parseGitLabTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return parsed
}
