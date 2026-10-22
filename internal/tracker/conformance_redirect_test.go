package tracker_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
	trackergithub "github.com/footprintai/containarium/internal/tracker/github"
	trackergitlab "github.com/footprintai/containarium/internal/tracker/gitlab"
)

// TestProviderConformance_RefusesCrossOriginRedirect proves both tracker
// adapters reject an HTTP redirect before a credential-bearing request reaches
// the redirected host. GitLab uses PRIVATE-TOKEN, which net/http does not
// strip automatically on a cross-host redirect.
func TestProviderConformance_RefusesCrossOriginRedirect(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider tracker.ReaderProvider
	}{
		{"github", trackergithub.New(nil)},
		{"gitlab", trackergitlab.New(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var decoyHits atomic.Int32
			decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				decoyHits.Add(1)
				if r.Header.Get("Authorization") != "" || r.Header.Get("PRIVATE-TOKEN") != "" {
					t.Errorf("%s: credential header reached the redirected host", tc.name)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(decoy.Close)

			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, decoy.URL+"/stolen", http.StatusFound)
			}))
			t.Cleanup(origin.Close)

			_, err := tc.provider.GetIssue(context.Background(), tracker.Conn{
				BaseURL:    origin.URL,
				Project:    "acme/widgets",
				Credential: "secret",
			}, 1)
			if !errors.Is(err, tracker.ErrCrossOriginRedirect) {
				t.Fatalf("GetIssue error = %v, want ErrCrossOriginRedirect", err)
			}
			if got := decoyHits.Load(); got != 0 {
				t.Fatalf("redirected host received %d request(s), want 0", got)
			}
		})
	}
}
