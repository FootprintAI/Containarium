package mcp

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #2529. A message with no "id" is a JSON-RPC notification, and the server must
// not reply to one. It used to answer notifications/initialized — sent on every
// MCP connection — with an error whose id is null, which Claude Code's strict
// client rejects, dropping the connection; the agent then had no tools.

func newNotificationTestServer(t *testing.T, token string) *Server {
	t.Helper()
	s, err := NewServer(&Config{ServerURL: "http://localhost:8080", JWTToken: token})
	require.NoError(t, err)
	return s
}

func TestHandleLine_NotificationsGetNoReply(t *testing.T) {
	s := newNotificationTestServer(t, "test-token")
	for _, line := range []string{
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`,
		`{"jsonrpc":"2.0","method":"notifications/some/future/one"}`,
		// Not a notification METHOD, but a message with no id is a notification
		// all the same: it must not be executed or answered.
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_containers"}}`,
		`{"jsonrpc":"2.0","method":"does/not/exist"}`,
	} {
		resp, reply := s.handleLine([]byte(line))
		assert.False(t, reply, "no reply to %s", line)
		assert.Nil(t, resp, line)
	}
}

func TestHandleLine_RequestsStillGetReplies(t *testing.T) {
	s := newNotificationTestServer(t, "test-token")

	resp, reply := s.handleLine([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	require.True(t, reply)
	assert.Equal(t, float64(1), resp.ID)
	assert.Nil(t, resp.Error)

	// An unknown METHOD with an id is still -32601, echoing the id.
	resp, reply = s.handleLine([]byte(`{"jsonrpc":"2.0","id":"abc","method":"does/not/exist"}`))
	require.True(t, reply)
	assert.Equal(t, "abc", resp.ID)
	require.NotNil(t, resp.Error)
	assert.Equal(t, -32601, resp.Error.Code)

	// "id": null is a request (discouraged, but present), so it is answered.
	resp, reply = s.handleLine([]byte(`{"jsonrpc":"2.0","id":null,"method":"tools/list"}`))
	require.True(t, reply, "an explicit null id is a request, not a notification")
	assert.Nil(t, resp.Error)

	// Clients use ping as a liveness check.
	resp, reply = s.handleLine([]byte(`{"jsonrpc":"2.0","id":7,"method":"ping"}`))
	require.True(t, reply)
	assert.Equal(t, float64(7), resp.ID)
	assert.Nil(t, resp.Error)
	assert.NotNil(t, resp.Result)
}

// Not valid JSON has no id to echo, which is exactly when JSON-RPC defines an
// id:null error. That reply stays.
func TestHandleLine_ParseErrorKeepsItsNullIDReply(t *testing.T) {
	s := newNotificationTestServer(t, "test-token")
	resp, reply := s.handleLine([]byte(`hello`))
	require.True(t, reply)
	assert.Nil(t, resp.ID)
	require.NotNil(t, resp.Error)
	assert.Equal(t, -32700, resp.Error.Code)
}

// The regression, end to end: drive the real Start() loop with the exact
// handshake Claude Code sends and read what comes back. Before the fix the
// second line was {"id":null,"error":{"code":-32601,...}}.
func TestStart_HandshakeProducesNoReplyToTheInitializedNotification(t *testing.T) {
	s := newNotificationTestServer(t, "test-token")

	inR, inW, err := os.Pipe()
	require.NoError(t, err)
	outR, outW, err := os.Pipe()
	require.NoError(t, err)
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	t.Cleanup(func() { os.Stdin, os.Stdout = oldIn, oldOut })

	// The tools/list reply (93 tool schemas) is larger than a pipe buffer, so the
	// reader must already be draining while Start runs.
	type result struct {
		replies []map[string]any
		err     error
	}
	read := make(chan result, 1)
	go func() {
		var r result
		sc := bufio.NewScanner(outR)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var m map[string]any
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				r.err = err
				break
			}
			r.replies = append(r.replies, m)
		}
		read <- r
	}()

	done := make(chan error, 1)
	go func() { done <- s.Start() }()

	_, err = inW.WriteString(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}` + "\n" +
			`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")
	require.NoError(t, err)
	require.NoError(t, inW.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after stdin closed")
	}
	require.NoError(t, outW.Close())
	var got result
	select {
	case got = <-read:
	case <-time.After(10 * time.Second):
		t.Fatal("reader did not finish")
	}
	require.NoError(t, got.err)
	replies := got.replies
	require.Len(t, replies, 2, "one reply per REQUEST (initialize, tools/list), none for the notification")
	assert.Equal(t, float64(1), replies[0]["id"])
	assert.Equal(t, float64(2), replies[1]["id"])
	for _, r := range replies {
		assert.NotNil(t, r["id"], "no reply may carry a null id: %v", r)
		assert.Nil(t, r["error"], "%v", r)
	}
}

// --- the box token's scope vocabulary ---------------------------------------------

func listedToolNames(t *testing.T, s *Server) []string {
	t.Helper()
	resp := s.handleToolsList(&MCPRequest{JSONRPC: "2.0", ID: 1, Method: "tools/list"})
	raw, err := json.Marshal(resp.Result)
	require.NoError(t, err)
	var res struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(raw, &res))
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	return names
}

// A box principal token carries "git:credential" and "mcp:user", which no tool
// requires; filtering by them listed ZERO tools, so the agent had none.
func TestToolsList_BoxTokenGetsTheCatalog(t *testing.T) {
	box := newNotificationTestServer(t, makeUnsignedJWT(t, map[string]interface{}{
		"username": "cld-1ab85347", "scopes": []string{"git:credential", "mcp:user"},
	}))
	unrestricted := newNotificationTestServer(t, "opaque-token")

	got := listedToolNames(t, box)
	assert.NotEmpty(t, got, "a box token must see tools")
	assert.ElementsMatch(t, listedToolNames(t, unrestricted), got,
		"mcp:user steps the advisory filter aside: the control plane enforces the person's role")
	assert.Contains(t, got, "tracker_list_issues")
}

func TestToolsList_BoxTokenToolCallsAreNotBlockedByTheFilter(t *testing.T) {
	box := newNotificationTestServer(t, makeUnsignedJWT(t, map[string]interface{}{
		"scopes": []string{"git:credential", "mcp:user"},
	}))
	assert.Nil(t, box.allowedScopes(), "no client-side narrowing for a box token")
}

// The filter still narrows for tokens that do NOT carry mcp:user — the change is
// one explicit scope, not a loosening of the filter.
func TestToolsList_OtherScopedTokensStillNarrow(t *testing.T) {
	readOnly := newNotificationTestServer(t, makeUnsignedJWT(t, map[string]interface{}{
		"scopes": []string{"containers:read"},
	}))
	got := listedToolNames(t, readOnly)
	assert.NotEmpty(t, got)
	assert.NotContains(t, got, "create_container", "a read-only token must not see write tools")

	// A scope vocabulary that is neither OSS tool scopes nor mcp:user still lists nothing:
	// that is the documented behaviour of the advisory filter and is left as it was.
	foreign := newNotificationTestServer(t, makeUnsignedJWT(t, map[string]interface{}{
		"scopes": []string{"git:credential"},
	}))
	assert.Empty(t, listedToolNames(t, foreign))
}

func TestHasScope(t *testing.T) {
	assert.True(t, hasScope([]string{"a", " mcp:user "}, "mcp:user"), "whitespace is trimmed, as in auth.HasScope")
	assert.False(t, hasScope(nil, "mcp:user"))
	assert.False(t, hasScope([]string{"mcp:users"}, "mcp:user"))
}
