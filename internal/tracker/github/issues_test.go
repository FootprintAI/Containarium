package github

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

func TestGetIssue_NormalizesFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/repos/acme/widgets/issues/42":
			_, _ = w.Write([]byte(`{
				"number": 42, "title": "bug", "body": "it broke",
				"state": "open",
				"labels": [{"name": "bug"}, {"name": "p1"}],
				"assignee": {"login": "alice"}
			}`))
		case "/repos/acme/widgets/issues/42/comments":
			_, _ = w.Write([]byte(`[
				{"user": {"login": "bob"}, "created_at": "2027-01-01T00:00:00Z", "body": "looking into it"}
			]`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	a := New(nil)
	issue, err := a.GetIssue(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "ghp_x"}, 42)
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if issue.Number != 42 || issue.Title != "bug" || issue.State != pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN {
		t.Errorf("issue = %+v, want number=42 title=bug state=OPEN", issue)
	}
	if len(issue.Labels) != 2 || issue.Labels[0] != "bug" || issue.Labels[1] != "p1" {
		t.Errorf("Labels = %v, want [bug p1]", issue.Labels)
	}
	if issue.Assignee != "alice" {
		t.Errorf("Assignee = %q, want alice", issue.Assignee)
	}
	if len(issue.Comments) != 1 || issue.Comments[0].Author != "bob" || issue.Comments[0].Body != "looking into it" {
		t.Errorf("Comments = %+v, want one comment from bob", issue.Comments)
	}
}

func TestGetIssue_UnassignedAndClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/repos/acme/widgets/issues/7":
			_, _ = w.Write([]byte(`{"number": 7, "title": "t", "body": "b", "state": "closed", "labels": [], "assignee": null}`))
		case "/repos/acme/widgets/issues/7/comments":
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()

	a := New(nil)
	issue, err := a.GetIssue(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, 7)
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if issue.Assignee != "" {
		t.Errorf("Assignee = %q, want empty (unassigned)", issue.Assignee)
	}
	if issue.State != pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED {
		t.Errorf("State = %v, want CLOSED", issue.State)
	}
	if issue.Comments != nil {
		t.Errorf("Comments = %v, want nil for an empty comment list", issue.Comments)
	}
}

func TestGetIssue_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()

	a := New(nil)
	_, err := a.GetIssue(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, 999)
	if !errors.Is(err, tracker.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestListIssues_FiltersOutPullRequests(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[
			{"number": 1, "title": "a real issue", "state": "open", "labels": []},
			{"number": 2, "title": "actually a PR", "state": "open", "labels": [], "pull_request": {}}
		]`))
	}))
	defer srv.Close()

	a := New(nil)
	issues, err := a.ListIssues(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, tracker.IssueFilter{})
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if len(issues) != 1 || issues[0].Number != 1 {
		t.Fatalf("issues = %+v, want exactly issue #1 (PR #2 filtered out)", issues)
	}
	if gotQuery == "" || !strings.Contains(gotQuery, "state=all") {
		t.Errorf("query = %q, want state=all for an unfiltered list", gotQuery)
	}
}

func TestListIssues_StateFilter(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	a := New(nil)
	_, err := a.ListIssues(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"},
		tracker.IssueFilter{State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN, Labels: []string{"bug", "p1"}})
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if !strings.Contains(gotQuery, "state=open") {
		t.Errorf("query = %q, want state=open", gotQuery)
	}
	if !strings.Contains(gotQuery, "labels=bug%2Cp1") {
		t.Errorf("query = %q, want labels=bug%%2Cp1", gotQuery)
	}
}

func TestListIssues_SearchRoutesToSearchAPI(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items": [{"number": 5, "title": "found me", "state": "open", "labels": []}]}`))
	}))
	defer srv.Close()

	a := New(nil)
	issues, err := a.ListIssues(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"},
		tracker.IssueFilter{Search: "found me"})
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if gotPath != "/search/issues" {
		t.Errorf("path = %q, want /search/issues", gotPath)
	}
	if len(issues) != 1 || issues[0].Number != 5 {
		t.Errorf("issues = %+v, want exactly issue #5", issues)
	}
}

func TestGetChange_MergedWithSuccessfulCI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/repos/acme/widgets/pulls/10":
			_, _ = w.Write([]byte(`{"number": 10, "state": "closed", "merged": true, "html_url": "https://github.com/acme/widgets/pull/10", "head": {"sha": "abc123"}}`))
		case "/repos/acme/widgets/commits/abc123/status":
			_, _ = w.Write([]byte(`{"state": "success", "total_count": 3}`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
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
	if change.URL != "https://github.com/acme/widgets/pull/10" {
		t.Errorf("URL = %q", change.URL)
	}
}

func TestGetChange_ClosedNotMerged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/repos/acme/widgets/pulls/11":
			_, _ = w.Write([]byte(`{"number": 11, "state": "closed", "merged": false, "head": {"sha": "def456"}}`))
		case "/repos/acme/widgets/commits/def456/status":
			_, _ = w.Write([]byte(`{"state": "failure", "total_count": 1}`))
		}
	}))
	defer srv.Close()

	a := New(nil)
	change, err := a.GetChange(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, 11)
	if err != nil {
		t.Fatalf("GetChange: %v", err)
	}
	if change.State != pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED {
		t.Errorf("State = %v, want CLOSED (closed but not merged)", change.State)
	}
	if change.CIVerdict != pb.TrackerCiVerdict_TRACKER_CI_VERDICT_FAILED {
		t.Errorf("CIVerdict = %v, want FAILED", change.CIVerdict)
	}
}

func TestGetChange_NoStatusesIsNoneVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/repos/acme/widgets/pulls/12":
			_, _ = w.Write([]byte(`{"number": 12, "state": "open", "merged": false, "head": {"sha": "ghi789"}}`))
		case "/repos/acme/widgets/commits/ghi789/status":
			_, _ = w.Write([]byte(`{"state": "pending", "total_count": 0}`))
		}
	}))
	defer srv.Close()

	a := New(nil)
	change, err := a.GetChange(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, 12)
	if err != nil {
		t.Fatalf("GetChange: %v", err)
	}
	if change.CIVerdict != pb.TrackerCiVerdict_TRACKER_CI_VERDICT_NONE {
		t.Errorf("CIVerdict = %v, want NONE (no CI configured — total_count 0)", change.CIVerdict)
	}
}
