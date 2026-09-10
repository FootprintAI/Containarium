package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHTTPClient_AddCollaborator_Success pins #1785: the client sends the
// owner/collaborator usernames, keys, and grant flags to the REST endpoint
// the daemon's ContainerServer.AddCollaborator exposes, and parses the
// collaborator + ssh_command back out of a grpc-gateway-shaped response.
func TestHTTPClient_AddCollaborator_Success(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"message": "Collaborator bob added to alice-container",
			"collaborator": {
				"ownerUsername": "alice",
				"collaboratorUsername": "bob",
				"containerName": "alice-container",
				"accountName": "alice-container-bob",
				"hasSudo": true
			},
			"sshCommand": "ssh -J jump alice-container-bob@jump"
		}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	resp, err := c.AddCollaborator("alice", "bob", []string{"ssh-ed25519 AAAA"}, true, false)
	if err != nil {
		t.Fatalf("AddCollaborator: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q; want POST", gotMethod)
	}
	if gotPath != "/v1/containers/alice/collaborators" {
		t.Errorf("path = %q; want /v1/containers/alice/collaborators", gotPath)
	}
	if gotBody["collaboratorUsername"] != "bob" {
		t.Errorf("collaboratorUsername = %v; want bob", gotBody["collaboratorUsername"])
	}
	if gotBody["grantSudo"] != true {
		t.Errorf("grantSudo = %v; want true", gotBody["grantSudo"])
	}
	if resp.GetCollaborator().GetAccountName() != "alice-container-bob" {
		t.Errorf("account name = %q; want alice-container-bob", resp.GetCollaborator().GetAccountName())
	}
	if resp.GetSshCommand() == "" {
		t.Errorf("ssh_command not parsed")
	}
}

// TestHTTPClient_RemoveCollaborator_Success pins the DELETE half of #1785.
func TestHTTPClient_RemoveCollaborator_Success(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message": "Collaborator bob removed from alice-container"}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	resp, err := c.RemoveCollaborator("alice", "bob")
	if err != nil {
		t.Fatalf("RemoveCollaborator: %v", err)
	}

	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", gotMethod)
	}
	if gotPath != "/v1/containers/alice/collaborators/bob" {
		t.Errorf("path = %q; want /v1/containers/alice/collaborators/bob", gotPath)
	}
	if resp.GetMessage() == "" {
		t.Errorf("message not parsed")
	}
}

// TestHTTPClient_ListCollaborators_Success pins the GET half of #1785.
func TestHTTPClient_ListCollaborators_Success(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"collaborators": [
				{"collaboratorUsername": "bob", "accountName": "alice-container-bob", "createdBy": "alice"},
				{"collaboratorUsername": "carol", "accountName": "alice-container-carol"}
			]
		}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	resp, err := c.ListCollaborators("alice")
	if err != nil {
		t.Fatalf("ListCollaborators: %v", err)
	}

	if gotMethod != http.MethodGet {
		t.Errorf("method = %q; want GET", gotMethod)
	}
	if gotPath != "/v1/containers/alice/collaborators" {
		t.Errorf("path = %q; want /v1/containers/alice/collaborators", gotPath)
	}
	if len(resp.GetCollaborators()) != 2 {
		t.Fatalf("got %d collaborators; want 2", len(resp.GetCollaborators()))
	}
	if resp.GetCollaborators()[0].GetCollaboratorUsername() != "bob" {
		t.Errorf("collaborators[0] username = %q; want bob", resp.GetCollaborators()[0].GetCollaboratorUsername())
	}
}

// TestHTTPClient_AddCollaborator_ErrorPropagated pins that a 4xx daemon
// error surfaces to the caller instead of being swallowed.
func TestHTTPClient_AddCollaborator_ErrorPropagated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "container alice-container does not exist"}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	_, err = c.AddCollaborator("alice", "bob", []string{"ssh-ed25519 AAAA"}, false, false)
	if err == nil {
		t.Fatalf("expected an error for a 400 response, got nil")
	}
}
