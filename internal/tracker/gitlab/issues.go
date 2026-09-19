package gitlab

import (
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

	var raw []glIssue
	if err := a.get(ctx, fmt.Sprintf("%s/projects/%s/issues?%s", apiBase, projectPath, q.Encode()), conn.Credential, &raw); err != nil {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", tracker.ErrUnreachable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		if out == nil {
			return nil
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%w: HTTP %d: %s", tracker.ErrCredentialInvalid, resp.StatusCode, string(body))
	case http.StatusNotFound:
		return fmt.Errorf("%w: %s", tracker.ErrNotFound, rawURL)
	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gitlab: HTTP %d: %s", resp.StatusCode, string(body))
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
