package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type fakeSessionsAPI struct {
	calls  []string
	closed bool
}

func (f *fakeSessionsAPI) TerminateUserSessions(username string) (*pb.TerminateUserSessionsResponse, error) {
	f.calls = append(f.calls, username)
	return &pb.TerminateUserSessionsResponse{TerminatedSessions: 4, BoxesTouched: 3}, nil
}

func (f *fakeSessionsAPI) Close() error { f.closed = true; return nil }

// The terminate_user_sessions tool is a thin wrapper over the CLI's shared
// client call (client.SessionsAPI.TerminateUserSessions), not an HTTP path of
// its own (#2522): with the shared client faked, the tool reaches the fake
// once and the MCP transport sends nothing.
func TestTerminateUserSessionsTool_CallsSharedClient(t *testing.T) {
	var ownRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ownRequests.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	fake := &fakeSessionsAPI{}
	var built *Client
	prev := newSessionsAPI
	newSessionsAPI = func(c *Client) (client.SessionsAPI, error) { built = c; return fake, nil }
	t.Cleanup(func() { newSessionsAPI = prev })

	c := NewClient(srv.URL, "tok")
	out, err := handleTerminateUserSessions(c, map[string]interface{}{"username": "alice"})
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, fake.calls, "exactly one shared-client call with the username")
	require.True(t, fake.closed)
	require.Same(t, c, built, "the shared client is built from the tool's own MCP client")
	require.Zero(t, ownRequests.Load(), "the MCP tool must not issue an HTTP request of its own")
	require.Contains(t, out, "alice")
	require.Contains(t, out, "4")
	require.Contains(t, out, "3")
}

// With the real factory, the request is the typed client's: the REST path
// from client.TerminateUserSessionsPath, carrying the MCP bearer.
func TestTerminateUserSessionsTool_RealClientPath(t *testing.T) {
	var method, path, bearer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path, bearer = r.Method, r.URL.EscapedPath(), r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"terminatedSessions":1,"boxesTouched":1}`)
	}))
	defer srv.Close()

	resp, err := NewClient(srv.URL, "tok").TerminateUserSessions("alice")
	require.NoError(t, err)
	require.Equal(t, http.MethodPost, method)
	require.Equal(t, client.TerminateUserSessionsPath("alice"), path)
	require.Equal(t, "Bearer tok", bearer)
	require.EqualValues(t, 1, resp.GetBoxesTouched())
}

func TestTerminateUserSessionsTool_RequiresUsernameAndSSHWrite(t *testing.T) {
	fake := &fakeSessionsAPI{}
	prev := newSessionsAPI
	newSessionsAPI = func(*Client) (client.SessionsAPI, error) { return fake, nil }
	t.Cleanup(func() { newSessionsAPI = prev })

	_, err := handleTerminateUserSessions(NewClient("http://127.0.0.1:1", "tok"), map[string]interface{}{})
	require.Error(t, err)
	require.Empty(t, fake.calls)

	srv := &Server{}
	srv.registerTools()
	for _, tool := range srv.tools {
		if tool.Name == "terminate_user_sessions" {
			require.Equal(t, auth.ScopeSSHWrite, tool.RequiredScope)
			return
		}
	}
	t.Fatal("terminate_user_sessions is not registered")
}
