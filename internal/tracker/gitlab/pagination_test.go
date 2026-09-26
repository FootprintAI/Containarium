package gitlab

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
// for exactly tracker.MaxListPages pages.
func TestListIssues_StopsAtMaxListPages(t *testing.T) {
	var requests int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&requests, 1)
		w.Header().Set("Link", fmt.Sprintf(`<%s/api/v4/projects/acme%%2Fwidgets/issues?page=%d>; rel="next"`, srv.URL, n+1))
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `[{"iid": %d, "title": "t", "state": "opened", "labels": []}]`, n)
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
