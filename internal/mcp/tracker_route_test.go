package mcp

// tracker_route_list (#2021) — thin wrapper over the same REST endpoint
// `containarium tracker route list` calls.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPClient_ListTrackerRoutes(t *testing.T) {
	var sawPath, sawMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath, sawMethod = r.URL.EscapedPath(), r.Method
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"routes":[{"username":"alice","connection":"a/b","scope":"product","skillId":"product-define"}]}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "tok")
	routes, err := c.ListTrackerRoutes(ListTrackerRoutesRequest{Username: "alice", Connection: "a/b"})
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, sawMethod)
	assert.Equal(t, "/v1/tracker/alice/a%2Fb/routes", sawPath)
	require.Len(t, routes, 1)
	assert.Equal(t, TrackerRoute{Username: "alice", Connection: "a/b", Scope: "product", SkillID: "product-define"}, routes[0])
}

func TestHandleTrackerRouteList(t *testing.T) {
	body := `{"routes":[{"username":"alice","connection":"default","scope":"product","skillId":"product-define"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()

	c := NewClient(server.URL, "tok")
	out, err := handleTrackerRouteList(c, map[string]interface{}{"username": "alice", "connection": "default"})
	require.NoError(t, err)
	assert.Contains(t, out, "scope:product")
	assert.Contains(t, out, "product-define")

	body = `{}`
	out, err = handleTrackerRouteList(c, map[string]interface{}{"username": "alice", "connection": "default"})
	require.NoError(t, err)
	assert.Contains(t, out, "No scope routes")
}

func TestTrackerRouteList_ScopeIsTrackerAdmin(t *testing.T) {
	assert.Equal(t, auth.ScopeTrackerAdmin, toolScopeAssignments()["tracker_route_list"])
}
