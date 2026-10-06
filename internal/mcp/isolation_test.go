package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// create_container is a thin wrapper over the same create call the CLI
// makes: `isolation: "vm"` must reach the daemon as the proto enum name
// (what grpc-gateway's protojson accepts), and nothing is sent when the
// argument is absent.
func TestCreateContainer_IsolationPassthrough(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		_, _ = w.Write([]byte(`{"container":{"name":"box1","username":"cld-1","state":"running"},"message":"created"}`))
	}))
	defer server.Close()

	_, err := handleCreateContainer(NewClient(server.URL, "t"), map[string]interface{}{
		"username":  "cld-1",
		"isolation": "vm",
	})
	require.NoError(t, err)
	assert.Contains(t, body, `"isolation":"ISOLATION_TYPE_VM"`)

	body = ""
	_, err = handleCreateContainer(NewClient(server.URL, "t"), map[string]interface{}{
		"username": "cld-1",
	})
	require.NoError(t, err)
	assert.False(t, strings.Contains(body, `"isolation"`), "absent argument must not be sent: %s", body)
}

func TestCreateContainer_IsolationInvalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("daemon must not be called for an invalid isolation value")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := handleCreateContainer(NewClient(server.URL, "t"), map[string]interface{}{
		"username":  "cld-1",
		"isolation": "bogus",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "isolation")
}
