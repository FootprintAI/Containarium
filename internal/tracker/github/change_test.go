package github_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
	trackergithub "github.com/footprintai/containarium/internal/tracker/github"
)

// TestOpenChange_DraftFlagSentAsIs proves GitHub's draft mechanic (a
// literal "draft" boolean field on the create-PR request) is exercised
// both ways — this is provider-specific behavior, deliberately outside
// the shared conformance suite, which only checks normalized output,
// not wire-level request shape.
func TestOpenChange_DraftFlagSentAsIs(t *testing.T) {
	for _, draft := range []bool{true, false} {
		var gotBody map[string]interface{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"number": 1, "state": "open", "html_url": "https://github.com/acme/widgets/pull/1"}`))
		}))
		defer srv.Close()

		adapter := trackergithub.New(nil)
		conn := tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "tok"}
		_, err := adapter.OpenChange(context.Background(), conn, tracker.OpenChangeRequest{
			HeadBranch:  "agent/run-1/1-x",
			BaseBranch:  "main",
			Title:       "Title",
			Description: "Body",
			Draft:       draft,
		})
		if err != nil {
			t.Fatalf("OpenChange(draft=%v): %v", draft, err)
		}
		gotDraft, _ := gotBody["draft"].(bool)
		if gotDraft != draft {
			t.Errorf("request body draft = %v, want %v (raw body: %+v)", gotDraft, draft, gotBody)
		}
		// GitHub's title/body must never carry a synthetic draft prefix
		// — that's GitLab's mechanism, not GitHub's.
		if title, _ := gotBody["title"].(string); title != "Title" {
			t.Errorf("request body title = %q, want unmodified %q", title, "Title")
		}
	}
}
