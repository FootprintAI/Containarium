package mcp

// Tests for #1145's MCP tools: add_collaborator / list_collaborators /
// remove_collaborator — the agent surface for box access a human already has
// via the CLI/REST/dashboard (its prerequisite, #1143, is already fixed:
// internal/client.{GRPCClient,HTTPClient} have typed collaborator methods).

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPClient_AddCollaborator(t *testing.T) {
	var sawHeader, sawPath, sawMethod string
	var sawBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header.Get("Authorization")
		sawPath = r.URL.Path
		sawMethod = r.Method
		_ = json.NewDecoder(r.Body).Decode(&sawBody)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"message":"ok","collaborator":{"collaboratorUsername":"bob","addedAt":"1771122760"}}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "ctnr_test.token")
	resp, err := c.AddCollaborator(AddCollaboratorRequest{
		OwnerUsername:        "alice",
		CollaboratorUsername: "bob",
		SSHPublicKeys:        []string{"ssh-ed25519 AAAAbob"},
		GrantSudo:            true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "Bearer ctnr_test.token", sawHeader, "add_collaborator must forward the bearer")
	assert.Equal(t, http.MethodPost, sawMethod)
	assert.Equal(t, "/v1/containers/alice/collaborators", sawPath, "owner_username must be path-escaped into the URL, not left in the body")
	assert.Equal(t, "bob", sawBody["collaboratorUsername"])
	assert.Equal(t, []any{"ssh-ed25519 AAAAbob"}, sawBody["sshPublicKeys"])
	assert.Equal(t, true, sawBody["grantSudo"])
	assert.NotContains(t, sawBody, "ownerUsername", "owner_username is path-bound (json:\"-\"), must not also ride in the body")
	assert.Equal(t, "bob", resp.Collaborator.CollaboratorUsername)
	assert.Equal(t, int64(1771122760), resp.Collaborator.AddedAt)
}

func TestMCPClient_ListCollaborators(t *testing.T) {
	var sawPath, sawMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		sawMethod = r.Method
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"collaborators":[{"collaboratorUsername":"bob","addedAt":"1"}],"totalCount":1}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "tok")
	resp, err := c.ListCollaborators("alice")
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, sawMethod)
	assert.Equal(t, "/v1/containers/alice/collaborators", sawPath)
	require.Len(t, resp.Collaborators, 1)
	assert.Equal(t, "bob", resp.Collaborators[0].CollaboratorUsername)
	assert.Equal(t, int32(1), resp.TotalCount)
}

func TestMCPClient_RemoveCollaborator(t *testing.T) {
	var sawPath, sawMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		sawMethod = r.Method
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"message":"removed"}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "tok")
	resp, err := c.RemoveCollaborator("alice", "bob")
	require.NoError(t, err)
	assert.Equal(t, http.MethodDelete, sawMethod)
	assert.Equal(t, "/v1/containers/alice/collaborators/bob", sawPath)
	assert.Equal(t, "removed", resp.Message)
}

// --- handler-level argument validation (mirrors TestHandleDeleteRoute_RequiresDomain) ---

func TestHandleAddCollaborator_RequiresOwnerUsername(t *testing.T) {
	_, err := handleAddCollaborator(nil, map[string]interface{}{
		"collaborator_username": "bob",
		"ssh_public_keys":       []interface{}{"ssh-ed25519 AAAA"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "owner_username is required")
}

func TestHandleAddCollaborator_RequiresCollaboratorUsername(t *testing.T) {
	_, err := handleAddCollaborator(nil, map[string]interface{}{
		"owner_username":  "alice",
		"ssh_public_keys": []interface{}{"ssh-ed25519 AAAA"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "collaborator_username is required")
}

func TestHandleAddCollaborator_RequiresSSHPublicKeys(t *testing.T) {
	_, err := handleAddCollaborator(nil, map[string]interface{}{
		"owner_username":        "alice",
		"collaborator_username": "bob",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh_public_keys is required")
}

func TestHandleListCollaborators_RequiresOwnerUsername(t *testing.T) {
	_, err := handleListCollaborators(nil, map[string]interface{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "owner_username is required")
}

func TestHandleRemoveCollaborator_RequiresBothUsernames(t *testing.T) {
	_, err := handleRemoveCollaborator(nil, map[string]interface{}{"owner_username": "alice"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "collaborator_username is required")

	_, err = handleRemoveCollaborator(nil, map[string]interface{}{"collaborator_username": "bob"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "owner_username is required")
}
