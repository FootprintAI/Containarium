package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Dispatch REST calls (#2022) — method + path (+ query) must match the
// google.api.http mapping on TrackerService in tracker.proto.

func TestTrackerDispatch_HTTPPathsAndDecoding(t *testing.T) {
	var gotMethod, gotPath, gotQuery, respBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotQuery = r.Method, r.URL.EscapedPath(), r.URL.RawQuery
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	respBody = `{"started":[{"id":"d1","issueNumber":"42","scope":"product","skillId":"product-define","runId":"r1","state":"TRACKER_DISPATCH_STATE_QUEUED"}],"skippedActive":2,"skippedUnrouted":1}`
	resp, err := c.DispatchTrackerIssues("alice", "a/b")
	if err != nil {
		t.Fatalf("DispatchTrackerIssues: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/tracker/alice/a%2Fb/dispatch" {
		t.Errorf("DispatchTrackerIssues %s %s, want POST /v1/tracker/alice/a%%2Fb/dispatch", gotMethod, gotPath)
	}
	if len(resp.GetStarted()) != 1 || resp.GetStarted()[0].GetIssueNumber() != 42 ||
		resp.GetStarted()[0].GetState() != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED ||
		resp.GetSkippedActive() != 2 || resp.GetSkippedUnrouted() != 1 {
		t.Errorf("DispatchTrackerIssues = %+v", resp)
	}

	respBody = `{"dispatches":[{"id":"d1","issueNumber":"42","state":"TRACKER_DISPATCH_STATE_RUNNING"}]}`
	rows, err := c.ListTrackerDispatches("alice", "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING)
	if err != nil {
		t.Fatalf("ListTrackerDispatches: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/tracker/alice/default/dispatches" || gotQuery != "state=TRACKER_DISPATCH_STATE_RUNNING" {
		t.Errorf("ListTrackerDispatches %s %s?%s, want GET /v1/tracker/alice/default/dispatches?state=TRACKER_DISPATCH_STATE_RUNNING", gotMethod, gotPath, gotQuery)
	}
	if len(rows) != 1 || rows[0].GetState() != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING {
		t.Errorf("ListTrackerDispatches = %+v", rows)
	}

	// UNSPECIFIED sends no state filter.
	respBody = `{}`
	if _, err := c.ListTrackerDispatches("alice", "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED); err != nil {
		t.Fatalf("ListTrackerDispatches (all): %v", err)
	}
	if gotQuery != "" {
		t.Errorf("unfiltered query = %q, want none", gotQuery)
	}
}
