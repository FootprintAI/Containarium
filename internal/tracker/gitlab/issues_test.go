package gitlab

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestGetIssue_NormalizesFieldsAndFiltersSystemNotes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		switch r.URL.EscapedPath() {
		case "/api/v4/projects/acme%2Fwidgets/issues/42":
			_, _ = w.Write([]byte(`{
				"iid": 42, "title": "bug", "description": "it broke",
				"state": "opened", "labels": ["bug", "p1"],
				"assignee": {"username": "alice"}
			}`))
		case "/api/v4/projects/acme%2Fwidgets/issues/42/notes":
			_, _ = w.Write([]byte(`[
				{"author": {"username": "bob"}, "created_at": "2027-01-01T00:00:00Z", "body": "looking into it", "system": false},
				{"author": {"username": "gitlab-bot"}, "created_at": "2027-01-01T00:01:00Z", "body": "assigned to @alice", "system": true}
			]`))
		default:
			t.Errorf("unexpected path %q", r.URL.EscapedPath())
		}
	}))
	defer srv.Close()

	a := New(nil)
	issue, err := a.GetIssue(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "glpat-x"}, 42)
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if issue.Number != 42 || issue.Title != "bug" || issue.State != pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN {
		t.Errorf("issue = %+v, want number=42 title=bug state=OPEN", issue)
	}
	if len(issue.Labels) != 2 || issue.Labels[0] != "bug" {
		t.Errorf("Labels = %v, want [bug p1]", issue.Labels)
	}
	if issue.Assignee != "alice" {
		t.Errorf("Assignee = %q, want alice", issue.Assignee)
	}
	if len(issue.Comments) != 1 || issue.Comments[0].Author != "bob" {
		t.Errorf("Comments = %+v, want exactly bob's comment (system note filtered out)", issue.Comments)
	}
}

func TestGetIssue_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"404 Not found"}`))
	}))
	defer srv.Close()

	a := New(nil)
	_, err := a.GetIssue(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, 999)
	if !errors.Is(err, tracker.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestListIssues_StateLabelsAndSearch(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"iid": 1, "title": "x", "state": "opened", "labels": []}]`))
	}))
	defer srv.Close()

	a := New(nil)
	issues, err := a.ListIssues(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "group/sub/widgets"},
		tracker.IssueFilter{State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN, Labels: []string{"bug", "p1"}, Search: "crash"})
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if gotPath != "/api/v4/projects/group%2Fsub%2Fwidgets/issues" {
		t.Errorf("path = %q, want the URL-escaped project path", gotPath)
	}
	if !strings.Contains(gotQuery, "state=opened") {
		t.Errorf("query = %q, want state=opened", gotQuery)
	}
	if !strings.Contains(gotQuery, "labels=bug%2Cp1") {
		t.Errorf("query = %q, want labels=bug%%2Cp1", gotQuery)
	}
	if !strings.Contains(gotQuery, "search=crash") {
		t.Errorf("query = %q, want search=crash", gotQuery)
	}
	if len(issues) != 1 {
		t.Errorf("issues = %+v, want 1", issues)
	}
}

func TestListIssues_UnspecifiedStateOmitsParam(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	a := New(nil)
	if _, err := a.ListIssues(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, tracker.IssueFilter{}); err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if strings.Contains(gotQuery, "state=") {
		t.Errorf("query = %q, want no state param (GitLab has no \"all\" value)", gotQuery)
	}
}

func TestGetChange_MergedWithSuccessPipeline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"iid": 10, "state": "merged", "web_url": "https://gitlab.com/acme/widgets/-/merge_requests/10",
			"head_pipeline": {"status": "success"}
		}`))
	}))
	defer srv.Close()

	a := New(nil)
	change, err := a.GetChange(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, 10)
	if err != nil {
		t.Fatalf("GetChange: %v", err)
	}
	if change.State != pb.TrackerIssueState_TRACKER_ISSUE_STATE_MERGED {
		t.Errorf("State = %v, want MERGED", change.State)
	}
	if change.CIVerdict != pb.TrackerCiVerdict_TRACKER_CI_VERDICT_SUCCESS {
		t.Errorf("CIVerdict = %v, want SUCCESS", change.CIVerdict)
	}
}

func TestGetChange_NoPipelineIsNoneVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"iid": 11, "state": "opened", "web_url": "u", "head_pipeline": null}`))
	}))
	defer srv.Close()

	a := New(nil)
	change, err := a.GetChange(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, 11)
	if err != nil {
		t.Fatalf("GetChange: %v", err)
	}
	if change.CIVerdict != pb.TrackerCiVerdict_TRACKER_CI_VERDICT_NONE {
		t.Errorf("CIVerdict = %v, want NONE", change.CIVerdict)
	}
}

// TestPipelineToVerdict_ManualSkippedCanceledNeverSuccess pins the
// design note's explicit callout: these three GitLab pipeline statuses
// must never read as SUCCESS.
func TestPipelineToVerdict_ManualSkippedCanceledNeverSuccess(t *testing.T) {
	for _, status := range []string{"manual", "skipped", "canceled"} {
		t.Run(status, func(t *testing.T) {
			got := pipelineToVerdict(&glPipeline{Status: status})
			if got == pb.TrackerCiVerdict_TRACKER_CI_VERDICT_SUCCESS {
				t.Errorf("pipelineToVerdict(%q) = SUCCESS, want anything but SUCCESS", status)
			}
			if got != pb.TrackerCiVerdict_TRACKER_CI_VERDICT_NONE {
				t.Errorf("pipelineToVerdict(%q) = %v, want NONE", status, got)
			}
		})
	}
}

func TestPipelineToVerdict_RunningIsPending(t *testing.T) {
	if got := pipelineToVerdict(&glPipeline{Status: "running"}); got != pb.TrackerCiVerdict_TRACKER_CI_VERDICT_PENDING {
		t.Errorf("pipelineToVerdict(running) = %v, want PENDING", got)
	}
}

func TestGetChange_ProjectPathURLEscaped(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"iid": 1, "state": "opened", "web_url": "u"}`))
	}))
	defer srv.Close()

	a := New(nil)
	if _, err := a.GetChange(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "group/subgroup/widgets"}, 1); err != nil {
		t.Fatalf("GetChange: %v", err)
	}
	if gotPath != "/api/v4/projects/group%2Fsubgroup%2Fwidgets/merge_requests/1" {
		t.Errorf("path = %q, want the fully URL-escaped nested project path", gotPath)
	}
}
