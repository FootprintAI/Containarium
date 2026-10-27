package client

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sprintHTTPClient(t *testing.T, status int, body string, seen *http.Request) *HTTPClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = *r
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	c, err := NewHTTPClient(srv.URL, "tok")
	require.NoError(t, err)
	return c
}

func TestHTTPClient_GetSprintBoard_RequestAndDecode(t *testing.T) {
	var seen http.Request
	c := sprintHTTPClient(t, 200, `{"mirror":{"state":"SPRINT_MIRROR_STATE_PRESENT","renderedMarkdown":"## S","board":{"project":"acme/app","umbrella":"3","items":[{"number":"4","title":"T","blockers":["2"]}]}}}`, &seen)
	m, err := c.GetSprintBoard(GetSprintBoardRequest{OrgID: "org/1", Project: "acme/app", Number: 3})
	require.NoError(t, err)
	assert.Equal(t, "/v1/orgs/org%2F1/sprints/board", seen.URL.EscapedPath())
	assert.Equal(t, "TRACKER_PROVIDER_GITHUB", seen.URL.Query().Get("umbrella.provider"))
	assert.Equal(t, "3", seen.URL.Query().Get("umbrella.number"))
	assert.Equal(t, "Bearer tok", seen.Header.Get("Authorization"))
	assert.Equal(t, SprintMirrorStatePresent, m.State)
	assert.Equal(t, []int64{2}, m.Board.Items[0].Blockers)
}

func TestHTTPClient_ListSprints(t *testing.T) {
	var seen http.Request
	c := sprintHTTPClient(t, 200, `{"sprints":[{"umbrella":{"project":"acme/app","number":"9"},"state":"SPRINT_MIRROR_STATE_NOT_ENABLED"}]}`, &seen)
	got, err := c.ListSprints(ListSprintsRequest{OrgID: "o"})
	require.NoError(t, err)
	assert.Equal(t, "/v1/orgs/o/sprints", seen.URL.EscapedPath())
	require.Len(t, got, 1)
	assert.Equal(t, int64(9), got[0].Umbrella.Number)
}

func TestSprintErrors_StatusAndHostedControlPlaneDetection(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantHosted bool
	}{
		{"standalone daemon route miss", 404, `{"code":5,"message":"Not Found","details":[]}`, true},
		{"empty 404 body", 404, ``, true},
		{"hosted 404 for a real reason", 404, `{"code":5,"message":"repo not found"}`, false},
		{"server error", 503, `{"code":14,"message":"rate limited"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := sprintHTTPClient(t, tc.status, tc.body, nil)
			_, err := c.GetSprintBoard(GetSprintBoardRequest{OrgID: "o", Project: "a/b", Number: 1})
			require.Error(t, err)
			var se *HTTPStatusError
			require.True(t, errors.As(err, &se))
			assert.Equal(t, tc.status, se.Status)
			assert.Equal(t, tc.wantHosted, IsSprintRouteMissing(err))
		})
	}
}

func TestParseSprintProvider(t *testing.T) {
	for in, want := range map[string]TrackerProvider{"": TrackerProviderGitHub, "GitHub": TrackerProviderGitHub, " gitlab ": TrackerProviderGitLab} {
		got, err := ParseSprintProvider(in)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	_, err := ParseSprintProvider("svn")
	require.Error(t, err)
}

func TestFormatSprintBoard_States(t *testing.T) {
	out, err := FormatSprintBoard("a/b", 3, &SprintMirror{State: SprintMirrorStateNotEnabled})
	require.NoError(t, err)
	assert.Contains(t, out, "NOT_ENABLED")

	_, err = FormatSprintBoard("a/b", 3, &SprintMirror{State: SprintMirrorStateRejected})
	require.ErrorIs(t, err, ErrSprintMirrorRejected)

	_, err = FormatSprintBoard("a/b", 3, &SprintMirror{State: "SPRINT_MIRROR_STATE_UNSPECIFIED"})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrSprintMirrorRejected)
}
