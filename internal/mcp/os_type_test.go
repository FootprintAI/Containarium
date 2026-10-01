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

// create_container's os_type must reach the daemon as the OSType enum name
// (what grpc-gateway's protojson accepts) — before #2208 the schema
// advertised it and the handler silently dropped it.
func TestCreateContainer_OSTypePassthrough(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		_, _ = w.Write([]byte(`{"container":{"name":"box1","username":"cld-1","state":"running"},"message":"created"}`))
	}))
	defer server.Close()

	for arg, want := range map[string]string{"rocky9": "OS_TYPE_ROCKY_9", "rhel9": "OS_TYPE_RHEL_9", "ubuntu": "OS_TYPE_UBUNTU_2404"} {
		body = ""
		_, err := handleCreateContainer(NewClient(server.URL, "t"), map[string]interface{}{"username": "cld-1", "os_type": arg})
		require.NoError(t, err, arg)
		assert.Contains(t, body, `"osType":"`+want+`"`, arg)
	}

	body = ""
	_, err := handleCreateContainer(NewClient(server.URL, "t"), map[string]interface{}{"username": "cld-1"})
	require.NoError(t, err)
	assert.False(t, strings.Contains(body, `"osType"`), "absent argument must not be sent: %s", body)
}

func TestCreateContainer_OSTypeInvalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("daemon must not be called for an unknown os_type")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := handleCreateContainer(NewClient(server.URL, "t"), map[string]interface{}{"username": "cld-1", "os_type": "debian12"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "os_type")
}
