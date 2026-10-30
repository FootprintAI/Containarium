package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeZapRisk(t *testing.T) {
	cases := []struct{ in, want string }{
		{"High", "high"},
		{"medium", "medium"},
		{"LOW", "low"},
		{"Informational", "info"},
		{"Info", "info"},
		{"unknown-stuff", "info"},
		{"", "info"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, normalizeZapRisk(c.in), "input %q", c.in)
	}
}

func TestGetInt64Arg(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		key  string
		want int64
		ok   bool
	}{
		{"missing", map[string]interface{}{}, "id", 0, false},
		{"int64", map[string]interface{}{"id": int64(42)}, "id", 42, true},
		{"int", map[string]interface{}{"id": 7}, "id", 7, true},
		{"float64 (JSON shape)", map[string]interface{}{"id": float64(13)}, "id", 13, true},
		{"string-parsable", map[string]interface{}{"id": "99"}, "id", 99, true},
		{"string-unparseable", map[string]interface{}{"id": "abc"}, "id", 0, false},
		{"wrong type", map[string]interface{}{"id": []int{1, 2}}, "id", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := getInt64Arg(c.args, c.key)
			assert.Equal(t, c.want, got)
			assert.Equal(t, c.ok, ok)
		})
	}
}

// #2659: install_clamav posts the box name to the daemon's install route and
// the handler refuses a missing name before any request is made.
func TestClientInstallClamav(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/security/clamav-install", r.URL.Path)
		var body map[string]string
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "alice-container", body["container_name"])
		_ = json.NewEncoder(w).Encode(InstallClamavResponse{Outcome: "CLAMAV_INSTALL_OUTCOME_INSTALLED", Message: "ok"})
	}))
	defer srv.Close()

	resp, err := NewClient(srv.URL, "test-token").InstallClamav("alice-container")
	require.NoError(t, err)
	assert.Equal(t, "CLAMAV_INSTALL_OUTCOME_INSTALLED", resp.Outcome)

	out, err := handleInstallClamav(NewClient(srv.URL, "test-token"), map[string]interface{}{"container_name": "alice-container"})
	require.NoError(t, err)
	assert.Contains(t, out, "CLAMAV_INSTALL_OUTCOME_INSTALLED")

	_, err = handleInstallClamav(NewClient(srv.URL, "test-token"), map[string]interface{}{})
	assert.ErrorContains(t, err, "container_name is required")
}
