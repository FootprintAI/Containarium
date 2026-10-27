package cmd

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runSprint runs `containarium sprint <args>` against an httptest server and
// returns stdout and the command error (non-nil means a non-zero exit).
func runSprint(t *testing.T, status int, body string, seen *http.Request, args ...string) (string, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = *r
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	oldServer, oldToken := serverAddr, authToken
	t.Cleanup(func() { serverAddr, authToken = oldServer, oldToken })
	t.Setenv("HOME", t.TempDir()) // never read a developer's credentials file
	return execSprint(t, append([]string{"--server", srv.URL, "--token", "tok"}, args...))
}

func execSprint(t *testing.T, args []string) (string, error) {
	t.Helper()
	// cobra keeps flag values and Changed marks across Execute calls.
	for _, c := range []*cobra.Command{sprintBoardCmd, sprintListCmd} {
		c.Flags().VisitAll(func(f *pflag.Flag) { _ = f.Value.Set(f.DefValue); f.Changed = false })
	}
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs(append([]string{"sprint"}, args...))
	t.Cleanup(func() { rootCmd.SetArgs(nil); rootCmd.SetOut(nil); rootCmd.SetErr(nil) })
	err := rootCmd.Execute()
	return out.String(), err
}

const sprintBoardBody = `{"mirror":{"state":"SPRINT_MIRROR_STATE_PRESENT","renderedMarkdown":"## Sprint 3\n- #4 ready",
 "board":{"project":"p","umbrella":"3","umbrellaTitle":"Sprint 3","items":[{"number":"4","title":"T","state":"SPRINT_ITEM_STATE_READY"}]}}}`

func TestSprintBoard_PrintsMarkdownAndSummary(t *testing.T) {
	var seen http.Request
	out, err := runSprint(t, 200, sprintBoardBody, &seen, "board", "--org", "o", "--project", "p", "--number", "3")
	require.NoError(t, err)
	assert.Equal(t, "/v1/orgs/o/sprints/board", seen.URL.Path)
	assert.Equal(t, "p", seen.URL.Query().Get("umbrella.project"))
	assert.Equal(t, "3", seen.URL.Query().Get("umbrella.number"))
	assert.Equal(t, "TRACKER_PROVIDER_GITHUB", seen.URL.Query().Get("umbrella.provider"))
	assert.Contains(t, out, "1 items")
	assert.Contains(t, out, "## Sprint 3\n- #4 ready")
}

func TestSprintBoard_GitLabProvider(t *testing.T) {
	var seen http.Request
	_, err := runSprint(t, 200, `{"mirror":{"state":"SPRINT_MIRROR_STATE_PROVIDER_NOT_SUPPORTED"}}`, &seen,
		"board", "--org", "o", "--project", "g/p", "--number", "3", "--provider", "gitlab")
	require.NoError(t, err)
	assert.Equal(t, "TRACKER_PROVIDER_GITLAB", seen.URL.Query().Get("umbrella.provider"))
}

func TestSprintBoard_NotEnabledPrintsAndExitsZero(t *testing.T) {
	out, err := runSprint(t, 200, `{"mirror":{"state":"SPRINT_MIRROR_STATE_NOT_ENABLED"}}`, nil,
		"board", "--org", "o", "--project", "p", "--number", "3")
	require.NoError(t, err)
	assert.Contains(t, out, "NOT_ENABLED")
}

func TestSprintBoard_RejectedExitsNonZero(t *testing.T) {
	_, err := runSprint(t, 200, `{"mirror":{"state":"SPRINT_MIRROR_STATE_REJECTED"}}`, nil,
		"board", "--org", "o", "--project", "p", "--number", "3")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "REJECTED")
}

func TestSprintBoard_RejectsBadFlags(t *testing.T) {
	for name, args := range map[string][]string{
		"no org":       {"board", "--project", "p", "--number", "3"},
		"no project":   {"board", "--org", "o", "--number", "3"},
		"zero number":  {"board", "--org", "o", "--project", "p"},
		"bad provider": {"board", "--org", "o", "--project", "p", "--number", "3", "--provider", "svn"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := runSprint(t, 200, sprintBoardBody, nil, args...)
			require.Error(t, err)
		})
	}
}

func TestSprint_StandaloneDaemonNeedsHostedControlPlane(t *testing.T) {
	for _, args := range [][]string{
		{"board", "--org", "o", "--project", "p", "--number", "3"},
		{"list", "--org", "o"},
	} {
		_, err := runSprint(t, 404, `{"code":5,"message":"Not Found","details":[]}`, nil, args...)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hosted control plane")
	}
}

func TestSprint_OtherServerErrorsAreNotRelabelled(t *testing.T) {
	_, err := runSprint(t, 503, `{"message":"rate limited"}`, nil, "list", "--org", "o")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "hosted control plane")
	assert.Contains(t, err.Error(), "503")
}

func TestSprintList_Prints(t *testing.T) {
	out, err := runSprint(t, 200, `{"sprints":[{"umbrella":{"project":"acme/app","number":"120"},"title":"Sprint 120","state":"SPRINT_MIRROR_STATE_PRESENT"}]}`, nil, "list", "--org", "o")
	require.NoError(t, err)
	assert.True(t, strings.Contains(out, "acme/app#120") && strings.Contains(out, "PRESENT"), out)
}

func TestSprint_RequiresServer(t *testing.T) {
	old := serverAddr
	t.Cleanup(func() { serverAddr = old })
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CONTAINARIUM_SERVER", "")
	_, err := execSprint(t, []string{"list", "--org", "o", "--server", ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--server")
}
