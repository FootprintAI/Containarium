package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bridge_dns_status wraps the same GET /v1/system/bridge-dns the CLI reads and
// returns the state without the enum's repeated prefix, like
// security_sentry_status does.
func TestHandleBridgeDNSStatus_DegradedIsNormalizedAndComplete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/system/bridge-dns", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		_, _ = w.Write([]byte(`{
			"state": "BRIDGE_DNS_STATE_DEGRADED",
			"reason": "bridgedns: write failed",
			"bridge": "incusbr0",
			"caddyIp": "10.0.3.5",
			"desired": "address=/example.com/10.0.3.5",
			"current": "address=/example.com/10.0.3.9",
			"lastError": "bridgedns: write failed",
			"driftCount": 3,
			"lastPass": "2026-09-30T12:00:00Z"
		}`))
	}))
	defer server.Close()

	out, err := handleBridgeDNSStatus(NewClient(server.URL, "test-token"), map[string]interface{}{})
	require.NoError(t, err)
	assert.Contains(t, out, `"state": "DEGRADED"`)
	assert.NotContains(t, out, "BRIDGE_DNS_STATE_")
	for _, want := range []string{"bridgedns: write failed", "10.0.3.5", "10.0.3.9", `"driftCount": 3`, "2026-09-30T12:00:00Z"} {
		assert.Contains(t, out, want)
	}
}

func TestHandleBridgeDNSStatus_InSync(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"state": "BRIDGE_DNS_STATE_IN_SYNC", "caddyIp": "10.0.3.5"}`))
	}))
	defer server.Close()

	out, err := handleBridgeDNSStatus(NewClient(server.URL, "test-token"), nil)
	require.NoError(t, err)
	assert.Contains(t, out, `"state": "IN_SYNC"`)
	assert.NotContains(t, out, "reason", "an in-sync response has no reason to show")
}

func TestHandleBridgeDNSStatus_APIErrorIsWrapped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"role required: admin"}`, http.StatusForbidden)
	}))
	defer server.Close()

	_, err := handleBridgeDNSStatus(NewClient(server.URL, "test-token"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bridge dns status")
	assert.Contains(t, err.Error(), "admin")
}

func TestBridgeDNSStatusToolIsRegistered(t *testing.T) {
	server, err := NewServer(&Config{ServerURL: "http://localhost:8080", JWTToken: "test-token"})
	require.NoError(t, err)
	var found bool
	for _, tool := range server.tools {
		if tool.Name == "bridge_dns_status" {
			found = true
			assert.NotNil(t, tool.Handler)
			assert.Empty(t, tool.InputSchema["required"], "takes no arguments")
		}
	}
	assert.True(t, found, "bridge_dns_status must be registered")
}

func TestCloudClientRefusesBridgeDNSStatus(t *testing.T) {
	_, err := cloudClient{}.GetBridgeDNSStatus()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bridge_dns_status")
}
