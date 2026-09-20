package gitlab_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
	trackergitlab "github.com/footprintai/containarium/internal/tracker/gitlab"
)

// TestOpenChange_DraftTitlePrefix proves GitLab's draft mechanic (a
// "Draft: " title prefix — GitLab has no dedicated boolean field on
// the create-MR endpoint) both fires when requested and does NOT
// double up if a caller's title already carries the prefix.
// Provider-specific, deliberately outside the shared conformance
// suite.
func TestOpenChange_DraftTitlePrefix(t *testing.T) {
	for _, tc := range []struct {
		name      string
		draft     bool
		title     string
		wantTitle string
	}{
		{"draft adds prefix", true, "My change", "Draft: My change"},
		{"non-draft leaves title alone", false, "My change", "My change"},
		{"draft does not double-prefix an already-prefixed title", true, "Draft: My change", "Draft: My change"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotBody map[string]interface{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&gotBody)
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"iid": 1, "state": "opened", "web_url": "https://gitlab.com/acme/widgets/-/merge_requests/1"}`))
			}))
			defer srv.Close()

			adapter := trackergitlab.New(nil)
			conn := tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "tok"}
			_, err := adapter.OpenChange(context.Background(), conn, tracker.OpenChangeRequest{
				HeadBranch:  "agent/run-1/1-x",
				BaseBranch:  "main",
				Title:       tc.title,
				Description: "Body",
				Draft:       tc.draft,
			})
			if err != nil {
				t.Fatalf("OpenChange: %v", err)
			}
			gotTitle, _ := gotBody["title"].(string)
			if gotTitle != tc.wantTitle {
				t.Errorf("request body title = %q, want %q", gotTitle, tc.wantTitle)
			}
		})
	}
}

func TestDefaultBranch(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"default_branch": "trunk"}`))
	}))
	defer srv.Close()

	adapter := trackergitlab.New(nil)
	conn := tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "tok"}
	branch, err := adapter.DefaultBranch(context.Background(), conn)
	if err != nil {
		t.Fatalf("DefaultBranch: %v", err)
	}
	if branch != "trunk" {
		t.Errorf("branch = %q, want trunk (never a hardcoded guess)", branch)
	}
	if gotPath != "/api/v4/projects/acme%2Fwidgets" {
		t.Errorf("path = %q, want /api/v4/projects/acme%%2Fwidgets", gotPath)
	}
}

func TestDefaultBranch_EmptyIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	adapter := trackergitlab.New(nil)
	conn := tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "tok"}
	if _, err := adapter.DefaultBranch(context.Background(), conn); err == nil {
		t.Error("want an error when GitLab reports no default branch, not a silent empty string")
	}
}
