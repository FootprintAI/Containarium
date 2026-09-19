package tracker_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
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
		provider tracker.ReaderProvider
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
	}
}

// newGitHubFixture serves the GitHub-shaped equivalent of the shared
// conformance scenario: issue #1 (open, labeled "bug", assigned to
// "agent", one comment from "reviewer"), a PR masquerading in the issues
// list (filtered out by ListIssues), and PR #2 (merged, CI success).
func newGitHubFixture(t *testing.T, fixedTime time.Time) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/repos/acme/widgets/issues/1":
			_, _ = w.Write([]byte(`{
				"number": 1, "title": "conformance issue", "body": "same body on every provider",
				"state": "open", "labels": [{"name": "bug"}], "assignee": {"login": "agent"}
			}`))
		case "/repos/acme/widgets/issues/1/comments":
			_, _ = w.Write([]byte(`[{"user": {"login": "reviewer"}, "created_at": "` + fixedTime.Format(time.RFC3339) + `", "body": "lgtm"}]`))
		case "/repos/acme/widgets/issues":
			_, _ = w.Write([]byte(`[
				{"number": 1, "title": "conformance issue", "body": "same body on every provider", "state": "open", "labels": [{"name": "bug"}], "assignee": {"login": "agent"}},
				{"number": 2, "title": "a pull request", "state": "open", "labels": [], "pull_request": {}}
			]`))
		case "/repos/acme/widgets/pulls/2":
			_, _ = w.Write([]byte(`{"number": 2, "state": "closed", "merged": true, "html_url": "https://github.com/acme/widgets/pull/2", "head": {"sha": "deadbeef"}}`))
		case "/repos/acme/widgets/commits/deadbeef/status":
			_, _ = w.Write([]byte(`{"state": "success", "total_count": 1}`))
		default:
			t.Errorf("github fixture: unexpected path %q", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// newGitLabFixture serves the GitLab-shaped equivalent of the same
// scenario.
func newGitLabFixture(t *testing.T, fixedTime time.Time) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		switch r.URL.EscapedPath() {
		case "/api/v4/projects/acme%2Fwidgets/issues/1":
			_, _ = w.Write([]byte(`{
				"iid": 1, "title": "conformance issue", "description": "same body on every provider",
				"state": "opened", "labels": ["bug"], "assignee": {"username": "agent"}
			}`))
		case "/api/v4/projects/acme%2Fwidgets/issues/1/notes":
			_, _ = w.Write([]byte(`[{"author": {"username": "reviewer"}, "created_at": "` + fixedTime.Format(time.RFC3339) + `", "body": "lgtm", "system": false}]`))
		case "/api/v4/projects/acme%2Fwidgets/issues":
			// GitLab has no "issue that is secretly a change" concept —
			// its issues and merge_requests are always separate
			// resources, so there's nothing to filter here. Returning
			// just issue #1 keeps the two fixtures' ListIssues result
			// identical without needing a GitLab-side equivalent of
			// GitHub's pull_request-in-issues-list quirk.
			_, _ = w.Write([]byte(`[{"iid": 1, "title": "conformance issue", "description": "same body on every provider", "state": "opened", "labels": ["bug"], "assignee": {"username": "agent"}}]`))
		case "/api/v4/projects/acme%2Fwidgets/merge_requests/2":
			_, _ = w.Write([]byte(`{"iid": 2, "state": "merged", "web_url": "https://gitlab.com/acme/widgets/-/merge_requests/2", "head_pipeline": {"status": "success"}}`))
		default:
			t.Errorf("gitlab fixture: unexpected path %q", r.URL.EscapedPath())
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
