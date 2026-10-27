package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestBuildSetSSHKeysRequest(t *testing.T) {
	f := filepath.Join(t.TempDir(), "k.pub")
	if err := os.WriteFile(f, []byte("ssh-ed25519 AAAA file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := buildSetSSHKeysRequest("b", []string{"ssh-ed25519 AAAA lit"}, []string{f}, false)
	if err != nil || len(req.SshPublicKeys) != 2 || req.SshPublicKeys[1] != "ssh-ed25519 AAAA file" || req.AllowEmpty {
		t.Fatalf("req=%+v err=%v", req, err)
	}
	if req, err := buildSetSSHKeysRequest("b", nil, nil, true); err != nil || !req.AllowEmpty || len(req.SshPublicKeys) != 0 {
		t.Fatalf("explicit empty: req=%+v err=%v", req, err)
	}
	// An omitted list must never become an empty replace-all.
	if _, err := buildSetSSHKeysRequest("b", nil, nil, false); err == nil {
		t.Fatal("no keys and no --empty accepted")
	}
	if _, err := buildSetSSHKeysRequest("b", []string{"k"}, nil, true); err == nil {
		t.Fatal("keys with --empty accepted")
	}
}

func TestConnectAPI_SetSSHKeys_PutsToGateway(t *testing.T) {
	var method, path string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		_, _ = w.Write([]byte(`{"message":"ok","removedKeys":2,"totalKeys":1}`))
	}))
	defer srv.Close()
	api := &connectAPI{hc: srv.Client(), server: srv.URL, token: "t"}
	resp, err := api.SetSSHKeys(context.Background(), &pb.SetSSHKeysRequest{Username: "b", SshPublicKeys: []string{"k"}})
	if err != nil {
		t.Fatal(err)
	}
	if method != "PUT" || path != "/v1/containers/b/ssh-keys" || resp.RemovedKeys != 2 || resp.TotalKeys != 1 {
		t.Fatalf("method=%s path=%s resp=%+v", method, path, resp)
	}
	if ks, _ := body["sshPublicKeys"].([]any); len(ks) != 1 {
		t.Fatalf("body = %v", body)
	}
}
