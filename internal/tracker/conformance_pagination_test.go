package tracker_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
	trackergithub "github.com/footprintai/containarium/internal/tracker/github"
	trackergitlab "github.com/footprintai/containarium/internal/tracker/gitlab"
)

// paginatedIssueCount is deliberately more than two full pages of 100,
// so an adapter that reads only the first page (#2040) sees 100 of them
// and one that stops after two sees 200.
const paginatedIssueCount = 250

// TestProviderConformance_ListIssuesFollowsPagination proves both
// adapters return every issue when the upstream splits the list over
// several pages linked by an RFC 8288 Link header (rel="next") — the
// mechanism both GitHub and GitLab use. Before #2040 each adapter read a
// single page of 100, so an older issue carrying a routed scope label
// was never seen by the dispatcher.
func TestProviderConformance_ListIssuesFollowsPagination(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider tracker.Provider
		baseURL  string
	}{
		{"github", trackergithub.New(nil), newPaginatedFixture(t, "/repos/acme/widgets/issues", "", githubIssueJSON)},
		{"gitlab", trackergitlab.New(nil), newPaginatedFixture(t, "/api/v4/projects/acme%2Fwidgets/issues", "", gitlabIssueJSON)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issues, err := tc.provider.ListIssues(context.Background(), tracker.Conn{BaseURL: tc.baseURL, Project: "acme/widgets"}, tracker.IssueFilter{Labels: []string{"scope:engineer"}})
			if err != nil {
				t.Fatalf("ListIssues: %v", err)
			}
			if len(issues) != paginatedIssueCount {
				t.Fatalf("%s ListIssues returned %d issues, want all %d across 3 pages", tc.name, len(issues), paginatedIssueCount)
			}
			seen := make(map[int64]bool, len(issues))
			for _, is := range issues {
				seen[is.Number] = true
			}
			for n := int64(1); n <= paginatedIssueCount; n++ {
				if !seen[n] {
					t.Fatalf("%s ListIssues missing issue #%d", tc.name, n)
				}
			}
		})
	}
}

// TestProviderConformance_ListIssuesRefusesCrossHostNextLink proves a
// Link header pointing at a different host is not followed: the adapter
// would otherwise send the tracker credential to whatever host the
// upstream response names. The next link targets a second, live server
// that counts every request it receives, so the test proves the
// credential never left — not merely that some error mentioning "host"
// came back (a DNS failure for an unresolvable decoy host would satisfy
// that too, even with the guard removed).
func TestProviderConformance_ListIssuesRefusesCrossHostNextLink(t *testing.T) {
	for _, tc := range []struct {
		name        string
		provider    tracker.Provider
		escapedPath string
		issueJSON   func(int) string
	}{
		{"github", trackergithub.New(nil), "/repos/acme/widgets/issues", githubIssueJSON},
		{"gitlab", trackergitlab.New(nil), "/api/v4/projects/acme%2Fwidgets/issues", gitlabIssueJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var decoyHits atomic.Int32
			decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				decoyHits.Add(1)
				if r.Header.Get("Authorization") != "" || r.Header.Get("PRIVATE-TOKEN") != "" {
					t.Errorf("%s: credential header reached the cross-host decoy", tc.name)
				}
				writeJSON(w, "[]")
			}))
			t.Cleanup(decoy.Close)

			baseURL := newPaginatedFixture(t, tc.escapedPath, decoy.URL, tc.issueJSON)
			_, err := tc.provider.ListIssues(context.Background(), tracker.Conn{BaseURL: baseURL, Project: "acme/widgets", Credential: "secret"}, tracker.IssueFilter{})
			if got := decoyHits.Load(); got != 0 {
				t.Fatalf("%s ListIssues sent %d request(s) to the cross-host next link, want 0", tc.name, got)
			}
			if !errors.Is(err, tracker.ErrCrossOriginNextLink) {
				t.Fatalf("%s ListIssues err = %v, want tracker.ErrCrossOriginNextLink", tc.name, err)
			}
		})
	}
}

func githubIssueJSON(n int) string {
	return fmt.Sprintf(`{"number": %d, "title": "issue %d", "state": "open", "labels": [{"name": "scope:engineer"}], "assignee": null}`, n, n)
}

func gitlabIssueJSON(n int) string {
	return fmt.Sprintf(`{"iid": %d, "title": "issue %d", "state": "opened", "labels": ["scope:engineer"], "assignee": null}`, n, n)
}

// newPaginatedFixture serves paginatedIssueCount issues, 100 per page,
// at escapedPath, linking each page to the next with a Link header.
// nextHost, when set, replaces the server's own origin in that link.
func newPaginatedFixture(t *testing.T, escapedPath, nextHost string, issueJSON func(int) string) string {
	t.Helper()
	const perPage = 100
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.EscapedPath() != escapedPath {
			t.Errorf("paginated fixture: unexpected request %s %q", r.Method, r.URL.EscapedPath())
			w.WriteHeader(http.StatusNotFound)
			return
		}
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			page, _ = strconv.Atoi(p)
		}
		first := (page-1)*perPage + 1
		last := page * perPage
		if last > paginatedIssueCount {
			last = paginatedIssueCount
		}
		if last < paginatedIssueCount {
			q := r.URL.Query()
			q.Set("page", strconv.Itoa(page+1))
			origin := srv.URL
			if nextHost != "" {
				origin = nextHost
			}
			next := origin + escapedPath + "?" + q.Encode()
			w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next", <%s>; rel="last"`, next, next))
		}
		items := make([]string, 0, perPage)
		for n := first; n <= last; n++ {
			items = append(items, issueJSON(n))
		}
		writeJSON(w, "["+strings.Join(items, ",")+"]")
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
