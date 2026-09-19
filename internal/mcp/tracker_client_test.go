package mcp

// Tests for #1922's tracker MCP tools' underlying *Client methods —
// wire-format shape (path, method, body, path-escaping) against an
// httptest server, mirroring collaborator_tools_test.go's pattern.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPClient_GetTrackerIssue(t *testing.T) {
	var sawPath, sawMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath, sawMethod = r.URL.Path, r.Method
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"issue":{"number":"7","title":"bug","body":"it broke","state":"TRACKER_ISSUE_STATE_OPEN","labels":["bug"],"assignee":"agent","comments":[{"author":"reviewer","createdAt":"2027-01-01T00:00:00Z","body":"looking"}]}}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "tok")
	issue, err := c.GetTrackerIssue(GetTrackerIssueRequest{Username: "alice", Connection: "default", Number: 7})
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, sawMethod)
	assert.Equal(t, "/v1/tracker/alice/default/issues/7", sawPath)
	assert.Equal(t, int64(7), issue.Number)
	assert.Equal(t, "bug", issue.Title)
	assert.Equal(t, "agent", issue.Assignee)
	require.Len(t, issue.Comments, 1)
	assert.Equal(t, "reviewer", issue.Comments[0].Author)
}

func TestMCPClient_GetTrackerIssue_PathEscapesConnectionName(t *testing.T) {
	var sawPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"issue":{"number":"1","title":"t","body":"","state":"TRACKER_ISSUE_STATE_OPEN"}}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "tok")
	_, err := c.GetTrackerIssue(GetTrackerIssueRequest{Username: "alice", Connection: "a/b", Number: 1})
	require.NoError(t, err)
	assert.Equal(t, "/v1/tracker/alice/a%2Fb/issues/1", sawPath)
}

func TestMCPClient_ListTrackerIssues_FiltersAsQueryParams(t *testing.T) {
	var sawQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"issues":[{"number":"1","title":"t","body":"","state":"TRACKER_ISSUE_STATE_OPEN"}]}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "tok")
	issues, err := c.ListTrackerIssues(ListTrackerIssuesRequest{
		Username: "alice", Connection: "default", State: "open", Labels: []string{"bug"}, Search: "crash",
	})
	require.NoError(t, err)
	require.Len(t, issues, 1)

	q, err := url.ParseQuery(sawQuery)
	require.NoError(t, err)
	assert.Equal(t, []string{"TRACKER_ISSUE_STATE_OPEN"}, q["state"])
	assert.Equal(t, []string{"bug"}, q["labels"])
	assert.Equal(t, []string{"crash"}, q["search"])
}

func TestMCPClient_GetTrackerChange(t *testing.T) {
	var sawPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"change":{"number":"2","state":"TRACKER_ISSUE_STATE_MERGED","ciVerdict":"TRACKER_CI_VERDICT_SUCCESS","url":"https://example.com/pr/2"}}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "tok")
	change, err := c.GetTrackerChange(GetTrackerChangeRequest{Username: "alice", Connection: "default", Number: 2})
	require.NoError(t, err)
	assert.Equal(t, "/v1/tracker/alice/default/changes/2", sawPath)
	assert.Equal(t, int64(2), change.Number)
	assert.Equal(t, "TRACKER_ISSUE_STATE_MERGED", change.State)
	assert.Equal(t, "TRACKER_CI_VERDICT_SUCCESS", change.CiVerdict)
}

func TestMCPClient_CommentOnTrackerIssue(t *testing.T) {
	var sawPath, sawMethod string
	var sawBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath, sawMethod = r.URL.Path, r.Method
		_ = json.NewDecoder(r.Body).Decode(&sawBody)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"comment":{"author":"agent-bot","createdAt":"2027-01-01T00:00:00Z","body":"hello"}}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "tok")
	comment, err := c.CommentOnTrackerIssue(CommentOnTrackerIssueRequest{
		Username: "alice", Connection: "default", Number: 7, Body: "hello",
	})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, sawMethod)
	assert.Equal(t, "/v1/tracker/alice/default/issues/7/comments", sawPath)
	assert.Equal(t, "hello", sawBody["body"])
	assert.NotContains(t, sawBody, "username", "path-bound fields must not also ride in the body")
	assert.Equal(t, "agent-bot", comment.Author)
}

func TestMCPClient_ClaimTrackerIssue(t *testing.T) {
	var sawPath string
	var sawBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&sawBody)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"claimed":true,"assigned":true}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "tok")
	result, err := c.ClaimTrackerIssue(ClaimTrackerIssueRequest{
		Username: "alice", Connection: "default", Number: 9, StaleAfterSeconds: 3600,
	})
	require.NoError(t, err)
	assert.Equal(t, "/v1/tracker/alice/default/issues/9/claim", sawPath)
	assert.Equal(t, float64(3600), sawBody["staleAfterSeconds"])
	assert.True(t, result.Claimed)
	assert.True(t, result.Assigned)
}

func TestMCPClient_ClaimTrackerIssue_AlreadyClaimed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"claimed":false,"alreadyClaimedByRunId":"run-other"}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "tok")
	result, err := c.ClaimTrackerIssue(ClaimTrackerIssueRequest{Username: "alice", Connection: "default", Number: 9})
	require.NoError(t, err)
	assert.False(t, result.Claimed)
	assert.Equal(t, "run-other", result.AlreadyClaimedByRunID)
}

func TestMCPClient_SetTrackerIssueLabels(t *testing.T) {
	var sawPath string
	var sawBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&sawBody)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"message":"labels updated"}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "tok")
	err := c.SetTrackerIssueLabels(SetTrackerIssueLabelsRequest{
		Username: "alice", Connection: "default", Number: 3,
		AddLabels: []string{"triaged"}, RemoveLabels: []string{"needs-triage"},
	})
	require.NoError(t, err)
	assert.Equal(t, "/v1/tracker/alice/default/issues/3/labels", sawPath)
	assert.Equal(t, []any{"triaged"}, sawBody["addLabels"])
	assert.Equal(t, []any{"needs-triage"}, sawBody["removeLabels"])
}
