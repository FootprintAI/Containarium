package mcp

// Asserts create/list/delete container output surfaces the RESOLVED backend/pool
// — so a placement that silently fell back to the default (cloud #686) is
// visible at the tool layer instead of via a later egress test.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListContainers_ShowsBackendAndPool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"containers":[{"name":"box1","username":"cld-1","state":"running","backendId":"tunnel-fts-13700k","pool":"gpu-pool"}],"totalCount":1}`))
	}))
	defer server.Close()

	out, err := handleListContainers(NewClient(server.URL, "t"), map[string]interface{}{})
	require.NoError(t, err)
	assert.Contains(t, out, "Backend: tunnel-fts-13700k")
	assert.Contains(t, out, "Pool: gpu-pool")
}

func TestCreateContainer_ShowsBackend_AndFallbackWarning(t *testing.T) {
	// Server reports the box landed on the default GCP backend, regardless of
	// the requested backend_id — the silent-fallback case.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"container":{"name":"box1","username":"cld-1","state":"running","backendId":"containarium-jump-ase1-spot"},"message":"created"}`))
	}))
	defer server.Close()

	out, err := handleCreateContainer(NewClient(server.URL, "t"), map[string]interface{}{
		"username":   "cld-1",
		"backend_id": "tunnel-fts-13700k", // requested
	})
	require.NoError(t, err)
	assert.Contains(t, out, "Backend: containarium-jump-ase1-spot")
	assert.Contains(t, out, "⚠️", "must warn when the box landed on a different backend than requested")
	assert.Contains(t, out, "tunnel-fts-13700k", "warning should name the requested backend")
}

func TestCreateContainer_NoWarningWhenBackendMatches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"container":{"name":"box1","username":"cld-1","state":"running","backendId":"tunnel-fts-13700k"},"message":"created"}`))
	}))
	defer server.Close()

	out, err := handleCreateContainer(NewClient(server.URL, "t"), map[string]interface{}{
		"username":   "cld-1",
		"backend_id": "tunnel-fts-13700k",
	})
	require.NoError(t, err)
	assert.Contains(t, out, "Backend: tunnel-fts-13700k")
	assert.NotContains(t, out, "⚠️", "no warning when landed backend == requested")
}

func TestDeleteContainer_ShowsBackend(t *testing.T) {
	// Delete pre-fetches the box (GET) to learn its backend, then deletes.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"container":{"name":"box1","username":"cld-1","state":"running","backendId":"tunnel-fts-13700k"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"message":"container cld-1 deleted","containerName":"cld-1"}`))
	}))
	defer server.Close()

	out, err := handleDeleteContainer(NewClient(server.URL, "t"), map[string]interface{}{"username": "cld-1"})
	require.NoError(t, err)
	assert.Contains(t, out, "deleted")
	assert.Contains(t, out, "Backend: tunnel-fts-13700k")
}

// The GET pre-fetch is best-effort: if it fails, delete still succeeds (just
// without the backend line).
func TestDeleteContainer_LookupFailureIsNonFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"message":"container cld-1 deleted","containerName":"cld-1"}`))
	}))
	defer server.Close()

	out, err := handleDeleteContainer(NewClient(server.URL, "t"), map[string]interface{}{"username": "cld-1"})
	require.NoError(t, err)
	assert.Contains(t, out, "deleted")
	assert.False(t, strings.Contains(out, "Backend:"), "no backend line when lookup failed")
}
