package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleSetSSHKeys_SendsPutWithExactList(t *testing.T) {
	var method, path string
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		b, _ := io.ReadAll(r.Body)
		require.NoError(t, json.Unmarshal(b, &got))
		_, _ = w.Write([]byte(`{"message":"SSH keys set for alice","removedKeys":1,"totalKeys":2}`))
	}))
	defer srv.Close()

	out, err := handleSetSSHKeys(NewClient(srv.URL, "tok"), map[string]interface{}{
		"username":        "alice",
		"ssh_public_keys": []interface{}{"k1", "k2"},
	})
	require.NoError(t, err)
	assert.Equal(t, "PUT", method)
	assert.Equal(t, "/v1/containers/alice/ssh-keys", path)
	assert.Equal(t, []interface{}{"k1", "k2"}, got["sshPublicKeys"])
	assert.Contains(t, out, "removed 1")
}

func TestHandleSetSSHKeys_Validation(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", "tok")
	_, err := handleSetSSHKeys(c, map[string]interface{}{})
	assert.Error(t, err)
	_, err = handleSetSSHKeys(c, map[string]interface{}{"username": "a", "ssh_public_keys": []interface{}{1}})
	assert.Error(t, err)
}
