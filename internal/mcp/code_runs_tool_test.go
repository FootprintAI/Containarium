package mcp

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// code_runs lists a box's run records over the same REST path
// `containarium code runs --http` uses, formatted by the same function.
func TestHandleCodeRuns(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/containers/alice/code-runs", r.URL.Path)
		_, _ = w.Write([]byte(`{"runs":[{"runName":"task","startedAt":"2026-09-28T10:00:00Z",` +
			`"endedAt":"2026-09-28T10:01:00Z","exitCode":0,"outcome":"BOX_RUN_OUTCOME_EXITED",` +
			`"logPath":"/tmp/agent-box/task.log","captureMode":"CAPTURE_MODE_FRAMED"}]}`))
	}))
	defer server.Close()

	out, err := handleCodeRuns(NewClient(server.URL, "test-token"), map[string]interface{}{"box": "alice"})
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 2, out)
	assert.Equal(t, []string{"task", "exited", "0", "2026-09-28T10:00:00Z", "2026-09-28T10:01:00Z", "-", "/tmp/agent-box/task.log"},
		strings.Fields(lines[1]))
}

func TestHandleCodeRuns_RequiresBox(t *testing.T) {
	_, err := handleCodeRuns(NewClient("http://127.0.0.1:0", "t"), map[string]interface{}{})
	require.Error(t, err)
}

// code_logs returns one bounded window plus end_offset (tail_log's shape).
func TestHandleCodeLogs_OneWindow(t *testing.T) {
	chunk := "hello from the agent\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/containers/alice/code-runs/task/log", r.URL.Path)
		assert.Equal(t, "40", r.URL.Query().Get("start_offset"))
		assert.Equal(t, "10", r.URL.Query().Get("follow_seconds"))
		_, _ = w.Write([]byte(`{"chunk":"` + base64.StdEncoding.EncodeToString([]byte(chunk)) +
			`","endOffset":"88","truncated":false,"ended":true,"stderrDropped":true}`))
	}))
	defer server.Close()

	out, err := handleCodeLogs(NewClient(server.URL, "test-token"), map[string]interface{}{
		"box": "alice", "run": "task", "start_offset": float64(40), "follow_seconds": float64(99),
	})
	require.NoError(t, err)
	assert.Equal(t, "end_offset: 88\nended: true\ntruncated: false\nstderr_dropped: true\n---\n"+chunk, out)
}

func TestHandleCodeLogs_RequiresBoxAndRun(t *testing.T) {
	c := NewClient("http://127.0.0.1:0", "t")
	_, err := handleCodeLogs(c, map[string]interface{}{"box": "alice"})
	require.Error(t, err)
	_, err = handleCodeLogs(c, map[string]interface{}{"run": "task"})
	require.Error(t, err)
}
