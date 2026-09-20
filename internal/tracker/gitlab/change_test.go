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
