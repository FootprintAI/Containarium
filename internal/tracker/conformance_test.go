package tracker_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/tracker"
	trackergithub "github.com/footprintai/containarium/internal/tracker/github"
	trackergitlab "github.com/footprintai/containarium/internal/tracker/gitlab"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestProviderConformance is the test the design note names to keep
// "provider-neutral" true: one suite, run against both adapters via the
// shared tracker.ReaderProvider interface, over fixtures built to
// represent the SAME logical issue/change on each provider's own wire
// shape. If the two adapters ever normalize an equivalent upstream
// response into different Go values, this fails — the whole point of
// the ReaderProvider contract is that a caller cannot tell which
// provider it's talking to from the shape of the answer.
func TestProviderConformance(t *testing.T) {
	fixedTime := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name     string
		provider tracker.WriterProvider
		conn     tracker.Conn
	}{
		{"github", trackergithub.New(nil), tracker.Conn{BaseURL: newGitHubFixture(t, fixedTime), Project: "acme/widgets"}},
		{"gitlab", trackergitlab.New(nil), tracker.Conn{BaseURL: newGitLabFixture(t, fixedTime), Project: "acme/widgets"}},
	} {
		t.Run(tc.name+"/GetIssue", func(t *testing.T) {
			issue, err := tc.provider.GetIssue(context.Background(), tc.conn, 1)
			if err != nil {
				t.Fatalf("GetIssue: %v", err)
			}
			want := tracker.Issue{
				Number:   1,
				Title:    "conformance issue",
				Body:     "same body on every provider",
				State:    pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN,
				Labels:   []string{"bug"},
				Assignee: "agent",
				Comments: []tracker.Comment{
					{Author: "reviewer", CreatedAt: fixedTime, Body: "lgtm"},
				},
			}
			if !reflect.DeepEqual(issue, want) {
				t.Errorf("%s GetIssue = %+v, want %+v", tc.name, issue, want)
			}
		})

		t.Run(tc.name+"/ListIssues_excludes changes", func(t *testing.T) {
			issues, err := tc.provider.ListIssues(context.Background(), tc.conn, tracker.IssueFilter{})
			if err != nil {
				t.Fatalf("ListIssues: %v", err)
			}
			if len(issues) != 1 || issues[0].Number != 1 {
				t.Errorf("%s ListIssues = %+v, want exactly issue #1 (the change-request-shaped entry excluded)", tc.name, issues)
			}
		})

		t.Run(tc.name+"/GetChange", func(t *testing.T) {
			change, err := tc.provider.GetChange(context.Background(), tc.conn, 2)
			if err != nil {
				t.Fatalf("GetChange: %v", err)
			}
			// URL is legitimately provider-specific — not compared.
			if change.Number != 2 {
				t.Errorf("%s GetChange.Number = %d, want 2", tc.name, change.Number)
			}
			if change.State != pb.TrackerIssueState_TRACKER_ISSUE_STATE_MERGED {
				t.Errorf("%s GetChange.State = %v, want MERGED", tc.name, change.State)
			}
			if change.CIVerdict != pb.TrackerCiVerdict_TRACKER_CI_VERDICT_SUCCESS {
				t.Errorf("%s GetChange.CIVerdict = %v, want SUCCESS", tc.name, change.CIVerdict)
			}
		})

		t.Run(tc.name+"/Comment", func(t *testing.T) {
			comment, err := tc.provider.Comment(context.Background(), tc.conn, 3, "conformance comment")
			if err != nil {
				t.Fatalf("Comment: %v", err)
			}
			if comment.Author != "reviewer" || comment.Body != "conformance comment" {
				t.Errorf("%s Comment = %+v, want author=reviewer body=%q", tc.name, comment, "conformance comment")
			}
		})

		t.Run(tc.name+"/AssignIfUnassigned_onUnassignedIssue", func(t *testing.T) {
			assigned, err := tc.provider.AssignIfUnassigned(context.Background(), tc.conn, 4)
			if err != nil {
				t.Fatalf("AssignIfUnassigned: %v", err)
			}
			if !assigned {
				t.Errorf("%s AssignIfUnassigned(unassigned issue) = false, want true", tc.name)
			}
		})

		t.Run(tc.name+"/AssignIfUnassigned_neverReplaces", func(t *testing.T) {
			assigned, err := tc.provider.AssignIfUnassigned(context.Background(), tc.conn, 1) // issue #1 is already assigned to "agent"
			if err != nil {
				t.Fatalf("AssignIfUnassigned: %v", err)
			}
			if assigned {
				t.Errorf("%s AssignIfUnassigned(already-assigned issue) = true, want false", tc.name)
			}
		})

		t.Run(tc.name+"/SetLabels", func(t *testing.T) {
			if err := tc.provider.SetLabels(context.Background(), tc.conn, 5, []string{"triaged"}, []string{"needs-triage"}); err != nil {
				t.Errorf("%s SetLabels: %v", tc.name, err)
			}
		})
	}
}

// newGitHubFixture serves the GitHub-shaped equivalent of the shared
// conformance scenario: issue #1 (open, labeled "bug", assigned to
// "agent", one comment from "reviewer"), a PR masquerading in the issues
// list (filtered out by ListIssues), and PR #2 (merged, CI success).
func newGitHubFixture(t *testing.T, fixedTime time.Time) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/acme/widgets/issues/1" && r.Method == http.MethodGet:
			writeJSON(w, `{
				"number": 1, "title": "conformance issue", "body": "same body on every provider",
				"state": "open", "labels": [{"name": "bug"}], "assignee": {"login": "agent"}
			}`)
		case r.URL.Path == "/repos/acme/widgets/issues/1/comments":
			writeJSON(w, `[{"user": {"login": "reviewer"}, "created_at": "`+fixedTime.Format(time.RFC3339)+`", "body": "lgtm"}]`)
		case r.URL.Path == "/repos/acme/widgets/issues" && r.Method == http.MethodGet:
			writeJSON(w, `[
				{"number": 1, "title": "conformance issue", "body": "same body on every provider", "state": "open", "labels": [{"name": "bug"}], "assignee": {"login": "agent"}},
				{"number": 2, "title": "a pull request", "state": "open", "labels": [], "pull_request": {}}
			]`)
		case r.URL.Path == "/repos/acme/widgets/pulls/2":
			writeJSON(w, `{"number": 2, "state": "closed", "merged": true, "html_url": "https://github.com/acme/widgets/pull/2", "head": {"sha": "deadbeef"}}`)
		case r.URL.Path == "/repos/acme/widgets/commits/deadbeef/status":
			writeJSON(w, `{"state": "success", "total_count": 1}`)
		case r.URL.Path == "/repos/acme/widgets/issues/3/comments" && r.Method == http.MethodPost:
			writeJSON(w, `{"user": {"login": "reviewer"}, "created_at": "`+fixedTime.Format(time.RFC3339)+`", "body": "conformance comment"}`)
		case r.URL.Path == "/repos/acme/widgets/issues/4" && r.Method == http.MethodGet:
			writeJSON(w, `{"number": 4, "title": "unassigned", "state": "open", "labels": [], "assignee": null}`)
		case r.URL.Path == "/user":
			writeJSON(w, `{"login": "agent-bot"}`)
		case r.URL.Path == "/repos/acme/widgets/issues/4/assignees" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		case r.URL.Path == "/repos/acme/widgets/issues/5/labels" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/repos/acme/widgets/issues/5/labels/"):
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("github fixture: unexpected request %s %q", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func writeJSON(w http.ResponseWriter, body string) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

// newGitLabFixture serves the GitLab-shaped equivalent of the same
// scenario.
func newGitLabFixture(t *testing.T, fixedTime time.Time) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.EscapedPath() == "/api/v4/projects/acme%2Fwidgets/issues/1" && r.Method == http.MethodGet:
			writeJSON(w, `{
				"iid": 1, "title": "conformance issue", "description": "same body on every provider",
				"state": "opened", "labels": ["bug"], "assignee": {"username": "agent"}
			}`)
		case r.URL.EscapedPath() == "/api/v4/projects/acme%2Fwidgets/issues/1/notes":
			writeJSON(w, `[{"author": {"username": "reviewer"}, "created_at": "`+fixedTime.Format(time.RFC3339)+`", "body": "lgtm", "system": false}]`)
		case r.URL.EscapedPath() == "/api/v4/projects/acme%2Fwidgets/issues" && r.Method == http.MethodGet:
			// GitLab has no "issue that is secretly a change" concept —
			// its issues and merge_requests are always separate
			// resources, so there's nothing to filter here. Returning
			// just issue #1 keeps the two fixtures' ListIssues result
			// identical without needing a GitLab-side equivalent of
			// GitHub's pull_request-in-issues-list quirk.
			writeJSON(w, `[{"iid": 1, "title": "conformance issue", "description": "same body on every provider", "state": "opened", "labels": ["bug"], "assignee": {"username": "agent"}}]`)
		case r.URL.EscapedPath() == "/api/v4/projects/acme%2Fwidgets/merge_requests/2":
			writeJSON(w, `{"iid": 2, "state": "merged", "web_url": "https://gitlab.com/acme/widgets/-/merge_requests/2", "head_pipeline": {"status": "success"}}`)
		case r.URL.EscapedPath() == "/api/v4/projects/acme%2Fwidgets/issues/3/notes" && r.Method == http.MethodPost:
			writeJSON(w, `{"author": {"username": "reviewer"}, "created_at": "`+fixedTime.Format(time.RFC3339)+`", "body": "conformance comment"}`)
		case r.URL.EscapedPath() == "/api/v4/projects/acme%2Fwidgets/issues/4" && r.Method == http.MethodGet:
			writeJSON(w, `{"iid": 4, "title": "unassigned", "state": "opened", "labels": [], "assignee": null}`)
		case r.URL.EscapedPath() == "/api/v4/user":
			writeJSON(w, `{"id": 99, "username": "agent-bot", "bot": true}`)
		case r.URL.EscapedPath() == "/api/v4/projects/acme%2Fwidgets/issues/4" && r.Method == http.MethodPut:
			writeJSON(w, `{}`)
		case r.URL.EscapedPath() == "/api/v4/projects/acme%2Fwidgets/issues/5" && r.Method == http.MethodPut:
			writeJSON(w, `{}`)
		default:
			t.Errorf("gitlab fixture: unexpected request %s %q", r.Method, r.URL.EscapedPath())
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
