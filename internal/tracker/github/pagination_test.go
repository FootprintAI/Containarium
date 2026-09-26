package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
)

// TestListIssues_StopsAtMaxListPages proves the pagination loop (#2040)
// is bounded: an upstream that always answers with a next link is read
// for exactly tracker.MaxListPages pages, and what was collected is
// returned rather than the call looping forever.
func TestListIssues_StopsAtMaxListPages(t *testing.T) {
	var requests int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&requests, 1)
		w.Header().Set("Link", fmt.Sprintf(`<%s/repos/acme/widgets/issues?page=%d>; rel="next"`, srv.URL, n+1))
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `[{"number": %d, "title": "t", "state": "open", "labels": []}]`, n)
	}))
	defer srv.Close()

	issues, err := New(nil).ListIssues(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, tracker.IssueFilter{})
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != tracker.MaxListPages {
		t.Errorf("upstream requests = %d, want exactly tracker.MaxListPages (%d)", got, tracker.MaxListPages)
	}
	if len(issues) != tracker.MaxListPages {
		t.Errorf("len(issues) = %d, want %d (one per page read)", len(issues), tracker.MaxListPages)
	}
}

// TestListIssues_SearchFollowsPagination covers the Search API branch,
// whose pages are {items: [...]} objects rather than bare arrays.
func TestListIssues_SearchFollowsPagination(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search/issues" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.URL.Query().Get("page") == "" {
			w.Header().Set("Link", fmt.Sprintf(`<%s/search/issues?q=x&page=2>; rel="next"`, srv.URL))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"total_count": 2, "items": [{"number": 1, "title": "a", "state": "open", "labels": []}]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"total_count": 2, "items": [{"number": 2, "title": "b", "state": "open", "labels": []}]}`))
	}))
	defer srv.Close()

	issues, err := New(nil).ListIssues(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, tracker.IssueFilter{Search: "crash"})
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if len(issues) != 2 || issues[0].Number != 1 || issues[1].Number != 2 {
		t.Errorf("issues = %+v, want #1 then #2 across two search pages", issues)
	}
}
