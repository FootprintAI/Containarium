package mcp

// Per-workstream test file for K3 + K4 of cloud#147 — assert the MCP
// `create_container` + `expose_port` tools dispatch correctly when
// the operator-supplied bearer is an API token (ctnr_<id>.<secret>
// shape) rather than a JWT.
//
// The cloud's JWTServerInterceptorWithAPITokens accepts both
// schemes — this test confirms the OSS MCP server forwards the
// bearer verbatim (no JWT-specific massaging) so an API-token
// caller doesn't get stuck at the cloud edge.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMCPClient_K3_CreateContainerAcceptsAPIToken — the create
// flow is the K3 acceptance path: handler → client.CreateContainer
// → POST /v1/containers with the API token in the Bearer header.
func TestMCPClient_K3_CreateContainerAcceptsAPIToken(t *testing.T) {
	const apiToken = "ctnr_abc123def456.deadbeefcafebabe1234567890abcdef"

	var sawHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"username":"alice","status":"created"}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, apiToken)
	resp, err := c.CreateContainer(CreateContainerRequest{
		Username: "alice",
		Image:    "ubuntu:22.04",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "Bearer "+apiToken, sawHeader,
		"MCP must forward the API token verbatim as a Bearer header")
}

// TestMCPClient_K4_ExposePortAcceptsAPIToken — same shape for
// the expose_port flow. The MCP server's expose_port tool wraps
// route creation; the client forwards the bearer.
func TestMCPClient_K4_ExposePortAcceptsAPIToken(t *testing.T) {
	const apiToken = "ctnr_xyz789.fedcba0987654321"

	var sawHeader, sawPath, sawMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header.Get("Authorization")
		sawPath = r.URL.Path
		sawMethod = r.Method
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"route":{"domain":"alice-myapp.example.dev"},"message":"ok"}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, apiToken)
	resp, err := c.AddRoute(AddRouteRequest{
		Domain:        "alice-myapp.example.dev",
		TargetIP:      "10.0.0.1",
		TargetPort:    8080,
		ContainerName: "alice",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "Bearer "+apiToken, sawHeader,
		"MCP expose_port must forward the API token verbatim")
	assert.True(t, strings.Contains(sawPath, "/routes"),
		"expose_port should target the routes endpoint (got %q)", sawPath)
	assert.Equal(t, http.MethodPost, sawMethod, "expose_port creates a route → POST")
}
