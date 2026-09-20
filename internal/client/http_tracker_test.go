package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestSetTrackerConnection_PathMethodAndBody(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"message": "connection created",
			"connection": {
				"username": "alice",
				"name": "default",
				"provider": "TRACKER_PROVIDER_GITHUB",
				"project": "acme/widgets",
				"credentialSecret": "GH_TOKEN"
			}
		}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	conn, msg, err := c.SetTrackerConnection(&pb.SetTrackerConnectionRequest{
		Username:         "alice",
		Name:             "default",
		Provider:         pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:          "acme/widgets",
		CredentialSecret: "GH_TOKEN",
	})
	if err != nil {
		t.Fatalf("SetTrackerConnection: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/v1/tracker/connections" {
		t.Errorf("path = %q, want /v1/tracker/connections", gotPath)
	}
	// The request body is built with protojson.Marshal on the generated
	// type, so field names come from the proto descriptor rather than a
	// hand-typed struct tag that could drift (#1219's class of bug).
	// Spot-check the fields that matter, rather than the exact bytes.
	bodyStr := string(gotBody)
	for _, want := range []string{`"username":"alice"`, `"project":"acme/widgets"`, `"credentialSecret":"GH_TOKEN"`} {
		if !strings.Contains(bodyStr, want) {
			t.Errorf("request body %s does not contain %s", bodyStr, want)
		}
	}
	if msg != "connection created" {
		t.Errorf("message = %q, want %q", msg, "connection created")
	}
	if conn.GetProvider() != pb.TrackerProvider_TRACKER_PROVIDER_GITHUB || conn.GetProject() != "acme/widgets" {
		t.Errorf("connection = %+v, want provider=GITHUB project=acme/widgets", conn)
	}
}

func TestListTrackerConnections_DecodesGatewayCamelCase(t *testing.T) {
	const gatewayJSON = `{
	  "connections": [
	    {
	      "username": "alice",
	      "name": "default",
	      "provider": "TRACKER_PROVIDER_GITLAB",
	      "baseUrl": "https://gitlab.example.com",
	      "project": "acme/widgets",
	      "credentialSecret": "GL_TOKEN"
	    }
	  ]
	}`

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(gatewayJSON))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	list, err := c.ListTrackerConnections("alice")
	if err != nil {
		t.Fatalf("ListTrackerConnections: %v", err)
	}
	if gotPath != "/v1/tracker/connections/alice" {
		t.Errorf("path = %q, want /v1/tracker/connections/alice", gotPath)
	}
	if len(list) != 1 {
		t.Fatalf("got %d connections, want 1", len(list))
	}
	if list[0].GetBaseUrl() != "https://gitlab.example.com" || list[0].GetProvider() != pb.TrackerProvider_TRACKER_PROVIDER_GITLAB {
		t.Errorf("connection = %+v, want baseUrl=https://gitlab.example.com provider=GITLAB", list[0])
	}
}

func TestDeleteTrackerConnection_PathAndMethod(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message": "connection default deleted"}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	msg, err := c.DeleteTrackerConnection("alice", "default")
	if err != nil {
		t.Fatalf("DeleteTrackerConnection: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/v1/tracker/connections/alice/default" {
		t.Errorf("path = %q, want /v1/tracker/connections/alice/default", gotPath)
	}
	if msg != "connection default deleted" {
		t.Errorf("message = %q, want %q", msg, "connection default deleted")
	}
}

func TestGetTrackerStatus_PathAndDecoding(t *testing.T) {
	const gatewayJSON = `{
	  "connection": {"username": "alice", "name": "default", "provider": "TRACKER_PROVIDER_GITHUB"},
	  "reachable": true,
	  "credentialValid": true,
	  "credentialBreadth": "TRACKER_CREDENTIAL_BREADTH_BROAD",
	  "credentialScopes": ["repo", "read:org"],
	  "credentialExpiresAt": "2027-05-01T00:00:00Z"
	}`

	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(gatewayJSON))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	resp, err := c.GetTrackerStatus("alice", "default")
	if err != nil {
		t.Fatalf("GetTrackerStatus: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if gotPath != "/v1/tracker/connections/alice/default/status" {
		t.Errorf("path = %q, want /v1/tracker/connections/alice/default/status", gotPath)
	}
	if !resp.GetReachable() || !resp.GetCredentialValid() {
		t.Errorf("Reachable=%v CredentialValid=%v, want both true", resp.GetReachable(), resp.GetCredentialValid())
	}
	if resp.GetCredentialBreadth() != pb.TrackerCredentialBreadth_TRACKER_CREDENTIAL_BREADTH_BROAD {
		t.Errorf("CredentialBreadth = %v, want BROAD", resp.GetCredentialBreadth())
	}
	if len(resp.GetCredentialScopes()) != 2 {
		t.Errorf("CredentialScopes = %v, want 2 entries", resp.GetCredentialScopes())
	}
	if resp.GetCredentialExpiresAt() == nil {
		t.Error("CredentialExpiresAt is nil, want the decoded timestamp")
	}
}

func TestGetTrackerIssue_PathAndDecoding(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"issue": {
				"number": 42, "title": "bug", "state": "TRACKER_ISSUE_STATE_OPEN",
				"labels": ["bug"], "assignee": "alice",
				"comments": [{"author": "bob", "body": "looking", "createdAt": "2027-01-01T00:00:00Z"}]
			}
		}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	issue, err := c.GetTrackerIssue(&pb.GetTrackerIssueRequest{Username: "alice", Connection: "default", Number: 42})
	if err != nil {
		t.Fatalf("GetTrackerIssue: %v", err)
	}
	if gotPath != "/v1/tracker/alice/default/issues/42" {
		t.Errorf("path = %q, want /v1/tracker/alice/default/issues/42", gotPath)
	}
	if issue.GetNumber() != 42 || issue.GetAssignee() != "alice" {
		t.Errorf("issue = %+v, want number=42 assignee=alice", issue)
	}
	if len(issue.GetComments()) != 1 || issue.GetComments()[0].GetAuthor() != "bob" {
		t.Errorf("Comments = %+v, want one comment from bob", issue.GetComments())
	}
}

func TestListTrackerIssues_QueryParams(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issues": [{"number": 1, "title": "a"}]}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	issues, err := c.ListTrackerIssues(&pb.ListTrackerIssuesRequest{
		Username: "alice", Connection: "default",
		State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN, Labels: []string{"bug", "p1"}, Search: "crash",
	})
	if err != nil {
		t.Fatalf("ListTrackerIssues: %v", err)
	}
	if gotPath != "/v1/tracker/alice/default/issues" {
		t.Errorf("path = %q, want /v1/tracker/alice/default/issues", gotPath)
	}
	if !strings.Contains(gotQuery, "state=TRACKER_ISSUE_STATE_OPEN") {
		t.Errorf("query = %q, want the state enum name", gotQuery)
	}
	if !strings.Contains(gotQuery, "labels=bug") || !strings.Contains(gotQuery, "labels=p1") {
		t.Errorf("query = %q, want both labels present as repeated params", gotQuery)
	}
	if !strings.Contains(gotQuery, "search=crash") {
		t.Errorf("query = %q, want search=crash", gotQuery)
	}
	if len(issues) != 1 {
		t.Errorf("issues = %+v, want 1", issues)
	}
}

func TestListTrackerIssues_UnfilteredOmitsQueryString(t *testing.T) {
	var gotRawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issues": []}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if _, err := c.ListTrackerIssues(&pb.ListTrackerIssuesRequest{Username: "alice", Connection: "default"}); err != nil {
		t.Fatalf("ListTrackerIssues: %v", err)
	}
	if gotRawQuery != "" {
		t.Errorf("query = %q, want empty for an unfiltered list", gotRawQuery)
	}
}

func TestGetTrackerChange_PathAndDecoding(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"change": {"number": 10, "state": "TRACKER_ISSUE_STATE_MERGED", "ciVerdict": "TRACKER_CI_VERDICT_SUCCESS", "url": "https://example.com/10"}}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	change, err := c.GetTrackerChange(&pb.GetTrackerChangeRequest{Username: "alice", Connection: "default", Number: 10})
	if err != nil {
		t.Fatalf("GetTrackerChange: %v", err)
	}
	if gotPath != "/v1/tracker/alice/default/changes/10" {
		t.Errorf("path = %q, want /v1/tracker/alice/default/changes/10", gotPath)
	}
	if change.GetState() != pb.TrackerIssueState_TRACKER_ISSUE_STATE_MERGED || change.GetCiVerdict() != pb.TrackerCiVerdict_TRACKER_CI_VERDICT_SUCCESS {
		t.Errorf("change = %+v, want state=MERGED ci_verdict=SUCCESS", change)
	}
}

func TestSubmitTrackerChange_PathMethodAndBody(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"change": {"number": 6, "state": "TRACKER_ISSUE_STATE_OPEN", "url": "https://example.com/6", "branch": "agent/run-1/1-x"}}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	change, err := c.SubmitTrackerChange(&pb.SubmitTrackerChangeRequest{
		Username: "alice", Connection: "default", Issue: 1, Title: "My change", Description: "does the thing",
	})
	if err != nil {
		t.Fatalf("SubmitTrackerChange: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/v1/tracker/alice/default/changes" {
		t.Errorf("path = %q, want /v1/tracker/alice/default/changes", gotPath)
	}
	if !strings.Contains(string(gotBody), `"title":"My change"`) {
		t.Errorf("request body = %s, want it to carry the title", gotBody)
	}
	if change.GetNumber() != 6 || change.GetBranch() != "agent/run-1/1-x" {
		t.Errorf("change = %+v, want number=6 branch=agent/run-1/1-x", change)
	}
}

func TestCommentOnTrackerIssue_PathMethodAndBody(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"comment": {"author": "agent-bot", "body": "hello"}}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	comment, err := c.CommentOnTrackerIssue(&pb.CommentOnTrackerIssueRequest{
		Username: "alice", Connection: "default", Number: 7, Body: "hello",
	})
	if err != nil {
		t.Fatalf("CommentOnTrackerIssue: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/v1/tracker/alice/default/issues/7/comments" {
		t.Errorf("path = %q, want /v1/tracker/alice/default/issues/7/comments", gotPath)
	}
	if !strings.Contains(string(gotBody), `"body":"hello"`) {
		t.Errorf("request body = %s, want it to carry the comment body", gotBody)
	}
	if comment.GetAuthor() != "agent-bot" {
		t.Errorf("comment = %+v, want author=agent-bot", comment)
	}
}

func TestClaimTrackerIssue_PathMethodAndDecoding(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"claimed": true, "assigned": true}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	result, err := c.ClaimTrackerIssue(&pb.ClaimTrackerIssueRequest{
		Username: "alice", Connection: "default", Number: 9, StaleAfterSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("ClaimTrackerIssue: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/v1/tracker/alice/default/issues/9/claim" {
		t.Errorf("path = %q, want /v1/tracker/alice/default/issues/9/claim", gotPath)
	}
	if !strings.Contains(string(gotBody), `"staleAfterSeconds":"3600"`) {
		t.Errorf("request body = %s, want the stale-after value (int64 fields marshal as strings in protojson)", gotBody)
	}
	if !result.GetClaimed() || !result.GetAssigned() {
		t.Errorf("result = %+v, want claimed=true assigned=true", result)
	}
}

func TestSetTrackerIssueLabels_PathMethodAndBody(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message": "labels updated"}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	msg, err := c.SetTrackerIssueLabels(&pb.SetTrackerIssueLabelsRequest{
		Username: "alice", Connection: "default", Number: 3,
		AddLabels: []string{"triaged"}, RemoveLabels: []string{"needs-triage"},
	})
	if err != nil {
		t.Fatalf("SetTrackerIssueLabels: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/v1/tracker/alice/default/issues/3/labels" {
		t.Errorf("path = %q, want /v1/tracker/alice/default/issues/3/labels", gotPath)
	}
	if !strings.Contains(string(gotBody), `"addLabels":["triaged"]`) || !strings.Contains(string(gotBody), `"removeLabels":["needs-triage"]`) {
		t.Errorf("request body = %s, want both label lists", gotBody)
	}
	if msg != "labels updated" {
		t.Errorf("message = %q, want %q", msg, "labels updated")
	}
}
