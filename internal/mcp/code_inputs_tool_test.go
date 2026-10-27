package mcp

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/footprintai/containarium/internal/coderun"
)

// code_answer reads the request's prompt, answers bound to it over the same
// REST paths `code answer --http` uses, and reports the box's response.
func TestHandleCodeAnswer_BindsTheListedPrompt(t *testing.T) {
	var answered map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/containers/alice/code-runs/task/inputs":
			_, _ = w.Write([]byte(`{"running":true,"open":[{"requestId":"req-0123456789abcdef","tool":"Bash","prompt":"Bash: make deploy","input":"{\"command\":\"make deploy\"}"}]}`))
		case "/v1/containers/alice/code-runs/task/inputs/req-0123456789abcdef:answer":
			assert.Equal(t, http.MethodPost, r.Method)
			b, _ := io.ReadAll(r.Body)
			require.NoError(t, json.Unmarshal(b, &answered))
			_, _ = w.Write([]byte(`{"outcome":"RUN_INPUT_ANSWER_OUTCOME_ANSWERED","closedAnswer":"RUN_INPUT_ANSWER_DENY","closeReason":"RUN_INPUT_CLOSE_REASON_ANSWERED"}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	out, err := handleCodeAnswer(NewClient(server.URL, "test-token"), map[string]interface{}{
		"box": "alice", "name": "task", "request_id": "req-0123456789abcdef", "input": `{"command":"make deploy"}`, "answer": "deny",
	})
	require.NoError(t, err)
	assert.Equal(t, "denied req-0123456789abcdef: Bash: make deploy\n", out)
	assert.Equal(t, "RUN_INPUT_ANSWER_DENY", answered["answer"])
	assert.Equal(t, base64.StdEncoding.EncodeToString(coderun.RequestDigest("Bash", `{"command":"make deploy"}`)), answered["requestSha256"])
}

func TestHandleCodeAnswer_AlreadyClosedIsAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"running":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"outcome":"RUN_INPUT_ANSWER_OUTCOME_ALREADY_CLOSED","closedAnswer":"RUN_INPUT_ANSWER_DENY","closeReason":"RUN_INPUT_CLOSE_REASON_EXPIRED"}`))
	}))
	defer server.Close()

	_, err := handleCodeAnswer(NewClient(server.URL, "test-token"), map[string]interface{}{
		"box": "alice", "request_id": "req-0123456789abcdef", "input": "{}", "answer": "allow",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already closed: deny (expired)")
}

func TestHandleCodeAnswer_RequiresArgs(t *testing.T) {
	c := NewClient("http://127.0.0.1:0", "t")
	_, err := handleCodeAnswer(c, map[string]interface{}{"box": "alice", "answer": "allow"})
	require.Error(t, err)
	_, err = handleCodeAnswer(c, map[string]interface{}{"box": "alice", "request_id": "req-0123456789abcdef", "input": "{}", "answer": "yes"})
	require.Error(t, err)
	_, err = handleCodeAnswer(c, map[string]interface{}{"box": "alice", "request_id": "req-0123456789abcdef", "answer": "allow"})
	require.ErrorContains(t, err, "`input` is required")
}

// An input that differs from the request's current one is refused before
// anything is sent (#2184 review).
func TestHandleCodeAnswer_ChangedPromptIsRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("an answer was sent: %s %s", r.Method, r.URL.Path)
			return
		}
		_, _ = w.Write([]byte(`{"running":true,"open":[{"requestId":"req-0123456789abcdef","tool":"Bash","prompt":"Bash: rm -rf ~/repo","input":"{\"command\":\"rm -rf ~/repo\"}"}]}`))
	}))
	defer server.Close()

	_, err := handleCodeAnswer(NewClient(server.URL, "test-token"), map[string]interface{}{
		"box": "alice", "request_id": "req-0123456789abcdef", "input": `{"command":"ls"}`, "answer": "allow",
	})
	require.ErrorContains(t, err, "request changed")
	assert.Contains(t, err.Error(), "Bash: rm -rf ~/repo")
}

func TestHandleCodePending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/containers/alice/code-runs/code/inputs", r.URL.Path)
		_, _ = w.Write([]byte(`{"running":true,"requests":1,"open":[{"requestId":"req-0123456789abcdef","prompt":"Bash: ls","input":"{}",` +
			`"createdAt":"2026-10-27T08:00:00Z","expiresAt":"2099-01-01T00:00:00Z"}]}`))
	}))
	defer server.Close()

	out, err := handleCodePending(NewClient(server.URL, "test-token"), map[string]interface{}{"box": "alice"})
	require.NoError(t, err)
	assert.Contains(t, out, "req-0123456789abcdef")
	assert.Contains(t, out, "Bash: ls")
	assert.Contains(t, out, "open 1)")
	// protojson varies its whitespace, so decode the JSON part.
	_, raw, ok := strings.Cut(out, "---\n")
	require.True(t, ok, out)
	var data struct {
		Open []struct {
			Prompt string `json:"prompt"`
			Input  string `json:"input"`
		} `json:"open"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &data))
	require.Len(t, data.Open, 1)
	assert.Equal(t, "Bash: ls", data.Open[0].Prompt)
	assert.Equal(t, "{}", data.Open[0].Input)
}
