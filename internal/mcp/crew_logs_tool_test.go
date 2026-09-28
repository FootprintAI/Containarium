package mcp

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// crew_logs returns one bounded window plus end_offset (tail_log's shape),
// read over the same REST path `containarium crew logs --http` uses.
func TestHandleCrewLogs_OneWindow(t *testing.T) {
	chunk := `{"seq":1,"kind":"status","text":"run started"}` + "\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/agent-runs/run-1/log", r.URL.Path)
		assert.Equal(t, "40", r.URL.Query().Get("start_offset"))
		assert.Equal(t, "reviewer", r.URL.Query().Get("skill_id"))
		assert.Equal(t, "10", r.URL.Query().Get("follow_seconds"))
		_, _ = w.Write([]byte(`{"chunk":"` + base64.StdEncoding.EncodeToString([]byte(chunk)) +
			`","endOffset":"88","truncated":false,"ended":true,"skillIds":["planner","reviewer"]}`))
	}))
	defer server.Close()

	out, err := handleCrewLogs(NewClient(server.URL, "test-token"), map[string]interface{}{
		"run_id": "run-1", "skill_id": "reviewer", "start_offset": float64(40), "follow_seconds": float64(99),
	})
	require.NoError(t, err)
	assert.Equal(t, "end_offset: 88\nended: true\ntruncated: false\nskill_ids: planner,reviewer\n---\n"+chunk, out)
}
