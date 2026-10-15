package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestHTTPDeployRecipe_GateRefusalMessage preserves both grpc-gateway and
// legacy error details when the daemon refuses a gated recipe.
func TestHTTPDeployRecipe_GateRefusalMessage(t *testing.T) {
	const message = "guardrail gate: guardrail_input with staging_ref and attestation is required"
	for _, body := range []string{`{"code":9,"message":"` + message + `"}`, `{"error":"` + message + `"}`} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, body)
			}))
			defer srv.Close()
			c, err := NewHTTPClient(srv.URL, "tok")
			require.NoError(t, err)
			_, err = c.DeployRecipe("gated", "alice", "", "", "", nil, nil)
			require.ErrorContains(t, err, message)
		})
	}
}
