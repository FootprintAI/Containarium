package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sprintPresentBody = `{"mirror":{
  "umbrella":{"provider":"TRACKER_PROVIDER_GITHUB","project":"acme/app","number":"120"},
  "state":"SPRINT_MIRROR_STATE_PRESENT",
  "renderedMarkdown":"## Sprint 120\n- #121 ready",
  "board":{"project":"acme/app","umbrella":"120","umbrellaTitle":"Sprint 120","partial":true,"partialReason":"rate limited",
    "items":[{"number":"121","title":"First","state":"SPRINT_ITEM_STATE_READY","blockers":["119"],"openBlockers":["119"]}]}}}`

func sprintServer(t *testing.T, status int, body string, seen *http.Request) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = *r
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "tok")
}

func TestClient_GetSprintBoard_RequestAndDecode(t *testing.T) {
	var seen http.Request
	c := sprintServer(t, 200, sprintPresentBody, &seen)

	m, err := c.GetSprintBoard(GetSprintBoardRequest{OrgID: "org/1", Project: "acme/app", Number: 120})
	require.NoError(t, err)
	require.NotNil(t, m)

	assert.Equal(t, http.MethodGet, seen.Method)
	assert.Equal(t, "/v1/orgs/org%2F1/sprints/board", seen.URL.EscapedPath())
	q := seen.URL.Query()
	assert.Equal(t, "TRACKER_PROVIDER_GITHUB", q.Get("umbrella.provider"), "provider defaults to GitHub")
	assert.Equal(t, "acme/app", q.Get("umbrella.project"))
	assert.Equal(t, "120", q.Get("umbrella.number"))

	assert.Equal(t, SprintMirrorStatePresent, m.State)
	assert.Equal(t, "## Sprint 120\n- #121 ready", m.RenderedMarkdown)
	require.NotNil(t, m.Board)
	assert.Equal(t, int64(120), m.Board.Umbrella)
	assert.True(t, m.Board.Partial)
	require.Len(t, m.Board.Items, 1)
	assert.Equal(t, int64(121), m.Board.Items[0].Number)
	assert.Equal(t, []int64{119}, m.Board.Items[0].OpenBlockers)
}

func TestClient_ListSprints_RequestAndDecode(t *testing.T) {
	var seen http.Request
	c := sprintServer(t, 200, `{"sprints":[{"umbrella":{"provider":"TRACKER_PROVIDER_GITHUB","project":"acme/app","number":"120"},"title":"Sprint 120","state":"SPRINT_MIRROR_STATE_NO_MIRROR_YET"}]}`, &seen)

	got, err := c.ListSprints(ListSprintsRequest{OrgID: "org-1"})
	require.NoError(t, err)
	assert.Equal(t, "/v1/orgs/org-1/sprints", seen.URL.EscapedPath())
	require.Len(t, got, 1)
	assert.Equal(t, int64(120), got[0].Umbrella.Number)
	assert.Equal(t, SprintMirrorStateNoMirrorYet, got[0].State)
}

func TestHandleSprintBoard_Present(t *testing.T) {
	c := sprintServer(t, 200, sprintPresentBody, nil)
	out, err := handleSprintBoard(c, map[string]interface{}{"org_id": "o", "project": "acme/app", "number": float64(120)})
	require.NoError(t, err)
	assert.Contains(t, out, "## Sprint 120\n- #121 ready", "rendered markdown is passed through verbatim")
	assert.Contains(t, out, "PRESENT")
	assert.Contains(t, out, "partial")
	assert.Contains(t, out, "rate limited")
}

func TestHandleSprintBoard_NonErrorStates(t *testing.T) {
	for state, want := range map[string]string{
		"SPRINT_MIRROR_STATE_NO_MIRROR_YET":          "no board yet",
		"SPRINT_MIRROR_STATE_NOT_ENABLED":            "not enabled",
		"SPRINT_MIRROR_STATE_PROVIDER_NOT_SUPPORTED": "not supported",
	} {
		t.Run(state, func(t *testing.T) {
			c := sprintServer(t, 200, `{"mirror":{"state":"`+state+`"}}`, nil)
			out, err := handleSprintBoard(c, map[string]interface{}{"org_id": "o", "project": "acme/app", "number": float64(120)})
			require.NoError(t, err, "%s is a result, not an error", state)
			assert.Contains(t, out, want)
			assert.Contains(t, out, state[len("SPRINT_MIRROR_STATE_"):], "state name is surfaced")
		})
	}
}

func TestHandleSprintBoard_RejectedIsError(t *testing.T) {
	c := sprintServer(t, 200, `{"mirror":{"state":"SPRINT_MIRROR_STATE_REJECTED"}}`, nil)
	_, err := handleSprintBoard(c, map[string]interface{}{"org_id": "o", "project": "acme/app", "number": float64(120)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "REJECTED")
}

func TestHandleSprintBoard_UnknownStateIsError(t *testing.T) {
	c := sprintServer(t, 200, `{"mirror":{"state":"SPRINT_MIRROR_STATE_UNSPECIFIED"}}`, nil)
	_, err := handleSprintBoard(c, map[string]interface{}{"org_id": "o", "project": "acme/app", "number": float64(120)})
	require.Error(t, err)
}

func TestHandleSprintBoard_RequiresArgs(t *testing.T) {
	c := sprintServer(t, 200, sprintPresentBody, nil)
	for name, args := range map[string]map[string]interface{}{
		"no org":     {"project": "a/b", "number": float64(1)},
		"no project": {"org_id": "o", "number": float64(1)},
		"no number":  {"org_id": "o", "project": "a/b"},
		"bad prov":   {"org_id": "o", "project": "a/b", "number": float64(1), "provider": "svn"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := handleSprintBoard(c, args)
			require.Error(t, err)
		})
	}
}

func TestHandleSprintBoard_GitLabProviderPassedThrough(t *testing.T) {
	var seen http.Request
	c := sprintServer(t, 200, `{"mirror":{"state":"SPRINT_MIRROR_STATE_PROVIDER_NOT_SUPPORTED"}}`, &seen)
	_, err := handleSprintBoard(c, map[string]interface{}{"org_id": "o", "project": "g/p", "number": float64(3), "provider": "gitlab"})
	require.NoError(t, err)
	assert.Equal(t, "TRACKER_PROVIDER_GITLAB", seen.URL.Query().Get("umbrella.provider"))
}

func TestHandleSprintBoard_APIErrorPropagates(t *testing.T) {
	c := sprintServer(t, 404, `{"message":"not found"}`, nil)
	_, err := handleSprintBoard(c, map[string]interface{}{"org_id": "o", "project": "a/b", "number": float64(1)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestHandleSprintList(t *testing.T) {
	c := sprintServer(t, 200, `{"sprints":[
	 {"umbrella":{"provider":"TRACKER_PROVIDER_GITHUB","project":"acme/app","number":"120"},"title":"Sprint 120","state":"SPRINT_MIRROR_STATE_PRESENT"},
	 {"umbrella":{"provider":"TRACKER_PROVIDER_GITHUB","project":"acme/web","number":"7"},"title":"Sprint 7","state":"SPRINT_MIRROR_STATE_NO_MIRROR_YET"}]}`, nil)
	out, err := handleSprintList(c, map[string]interface{}{"org_id": "o"})
	require.NoError(t, err)
	assert.Contains(t, out, "acme/app#120")
	assert.Contains(t, out, "Sprint 120")
	assert.Contains(t, out, "PRESENT")
	assert.Contains(t, out, "acme/web#7")
	assert.Contains(t, out, "NO_MIRROR_YET")

	_, err = handleSprintList(c, map[string]interface{}{})
	require.Error(t, err, "org_id is required")

	c = sprintServer(t, 200, `{}`, nil)
	out, err = handleSprintList(c, map[string]interface{}{"org_id": "o"})
	require.NoError(t, err)
	assert.Contains(t, out, "No sprints")
}

func TestSprintTools_RegisteredReadOnlyWithScope(t *testing.T) {
	assert.Equal(t, auth.ScopeTrackerRead, toolScopeAssignments()["sprint_board"])
	assert.Equal(t, auth.ScopeTrackerRead, toolScopeAssignments()["sprint_list"])
	names := map[string]bool{}
	for _, tl := range sprintTools() {
		names[tl.Name] = true
		assert.NotNil(t, tl.Handler)
	}
	assert.True(t, names["sprint_board"] && names["sprint_list"])
}

func TestClient_GetSprintBoard_DecodesTimestampsAndIdentity(t *testing.T) {
	c := sprintServer(t, 200, `{"mirror":{"state":"SPRINT_MIRROR_STATE_PRESENT","board":{"sprintId":"s1","provider":"SPRINT_PROVIDER_GITHUB","contentHash":"h","project":"acme/app","umbrella":"0",
	 "items":[{"number":"5","title":"T","rank":2,"state":"SPRINT_ITEM_STATE_RUNNING","runStatus":"SPRINT_RUN_STATUS_STARTED","runStartedAt":"2026-10-24T10:00:00Z","waitSince":"2026-10-24T09:00:00Z","prUrl":"https://example.com/pr/1","prState":"SPRINT_PR_STATE_OPEN","attention":["SPRINT_ATTENTION_PR_TO_MERGE"],"note":"n"}]}}}`, nil)
	m, err := c.GetSprintBoard(GetSprintBoardRequest{OrgID: "o", Project: "acme/app", Number: 1})
	require.NoError(t, err)
	b := m.Board
	require.NotNil(t, b)
	assert.Equal(t, "s1", b.SprintID)
	assert.Equal(t, "SPRINT_PROVIDER_GITHUB", b.Provider)
	assert.Equal(t, "h", b.ContentHash)
	it := b.Items[0]
	assert.Equal(t, int32(2), it.Rank)
	assert.Equal(t, "2026-10-24T10:00:00Z", it.RunStartedAt)
	assert.Equal(t, "2026-10-24T09:00:00Z", it.WaitSince)
	assert.Equal(t, []string{"SPRINT_ATTENTION_PR_TO_MERGE"}, it.Attention)
}

func TestSprintTools_ServerErrorsSurfaceStatusAndMessage(t *testing.T) {
	for status, body := range map[int]string{
		503: `{"code":14,"message":"the tracker is rate limiting reads; retry later"}`,
		404: `{"code":5,"message":"repo not found"}`,
	} {
		c := sprintServer(t, status, body, nil)
		_, err := handleSprintBoard(c, map[string]interface{}{"org_id": "o", "project": "a/b", "number": float64(1)})
		require.Error(t, err)
		assert.Contains(t, err.Error(), body[strings.Index(body, `"message":"`)+11:len(body)-2])
		_, err = handleSprintList(c, map[string]interface{}{"org_id": "o"})
		require.Error(t, err)
	}
}
