package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3288: FindOpenChange looks a branch's open pull request up by
// head=<owner>:<branch>, state=open.
func TestFindOpenChange(t *testing.T) {
	const branch = "containarium/issue-7"
	for _, tc := range []struct {
		name      string
		body      string
		wantFound bool
		wantNum   int64
	}{
		{"none open", `[]`, false, 0},
		{"one open", `[{"number": 5, "state": "open", "html_url": "https://github.com/acme/widgets/pull/5",
			"head": {"ref": "containarium/issue-7", "sha": "abc", "repo": {"full_name": "acme/widgets"}}}]`, true, 5},
		{"other branch ignored", `[{"number": 6, "state": "open", "html_url": "u",
			"head": {"ref": "other", "sha": "abc", "repo": {"full_name": "acme/widgets"}}}]`, false, 0},
		{"fork ignored", `[{"number": 8, "state": "open", "html_url": "u",
			"head": {"ref": "containarium/issue-7", "sha": "abc", "repo": {"full_name": "mallory/widgets"}}}]`, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath, gotHead, gotState string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotHead, gotState = r.URL.Path, r.URL.Query().Get("head"), r.URL.Query().Get("state")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			change, found, err := New(nil).FindOpenChange(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, branch)
			if err != nil {
				t.Fatalf("FindOpenChange: %v", err)
			}
			if gotPath != "/repos/acme/widgets/pulls" || gotHead != "acme:"+branch || gotState != "open" {
				t.Errorf("request = %s head=%q state=%q, want /repos/acme/widgets/pulls head=acme:%s state=open", gotPath, gotHead, gotState, branch)
			}
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v", found, tc.wantFound)
			}
			if !found {
				return
			}
			if change.Number != tc.wantNum || change.URL != "https://github.com/acme/widgets/pull/5" || change.Branch != branch ||
				change.State != pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN {
				t.Errorf("change = %+v, want #%d open on %s with its URL", change, tc.wantNum, branch)
			}
		})
	}
}

// #3288 (optional item): GetChange reports the pull request's head branch.
func TestGetChange_ReportsHeadBranch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/repos/acme/widgets/pulls/12" {
			_, _ = w.Write([]byte(`{"number": 12, "state": "open", "head": {"ref": "containarium/issue-7", "sha": ""}}`))
		}
	}))
	defer srv.Close()
	change, err := New(nil).GetChange(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, 12)
	if err != nil {
		t.Fatalf("GetChange: %v", err)
	}
	if change.Branch != "containarium/issue-7" {
		t.Errorf("Branch = %q, want the head branch", change.Branch)
	}
}
