package gitlab

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3288: FindOpenChange looks a branch's open merge request up by
// source_branch, state=opened, and ignores one opened from a fork's
// same-named branch.
func TestFindOpenChange(t *testing.T) {
	const branch = "containarium/issue-7"
	for _, tc := range []struct {
		name      string
		body      string
		wantFound bool
	}{
		{"none open", `[]`, false},
		{"one open", `[{"iid": 5, "state": "opened", "web_url": "https://gitlab.example/acme/widgets/-/merge_requests/5",
			"source_branch": "containarium/issue-7", "source_project_id": 3, "target_project_id": 3}]`, true},
		{"fork ignored", `[{"iid": 6, "state": "opened", "web_url": "u",
			"source_branch": "containarium/issue-7", "source_project_id": 99, "target_project_id": 3}]`, false},
		{"other branch ignored", `[{"iid": 7, "state": "opened", "web_url": "u",
			"source_branch": "other", "source_project_id": 3, "target_project_id": 3}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath, gotSource, gotState string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.EscapedPath()
				gotSource, gotState = r.URL.Query().Get("source_branch"), r.URL.Query().Get("state")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			change, found, err := New(nil).FindOpenChange(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, branch)
			if err != nil {
				t.Fatalf("FindOpenChange: %v", err)
			}
			if gotPath != "/api/v4/projects/acme%2Fwidgets/merge_requests" || gotSource != branch || gotState != "opened" {
				t.Errorf("request = %s source_branch=%q state=%q", gotPath, gotSource, gotState)
			}
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v", found, tc.wantFound)
			}
			if !found {
				return
			}
			if change.Number != 5 || change.URL != "https://gitlab.example/acme/widgets/-/merge_requests/5" || change.Branch != branch ||
				change.State != pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN || change.CIVerdict != pb.TrackerCiVerdict_TRACKER_CI_VERDICT_NONE {
				t.Errorf("change = %+v, want !5 open on %s with its URL", change, branch)
			}
		})
	}
}

// #3288 item 3: GetChange reports the merge request's source branch.
func TestGetChange_ReportsSourceBranch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"iid": 11, "state": "opened", "web_url": "u", "source_branch": "containarium/issue-7"}`))
	}))
	defer srv.Close()
	change, err := New(nil).GetChange(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, 11)
	if err != nil {
		t.Fatalf("GetChange: %v", err)
	}
	if change.Branch != "containarium/issue-7" {
		t.Errorf("Branch = %q, want the source branch", change.Branch)
	}
}
