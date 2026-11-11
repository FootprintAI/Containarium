package mcp

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/config"
	"github.com/footprintai/containarium/internal/credentials"
)

// #3581 (Q8): the pin for the reader side of the per-run token.
//
// A daemon-started run gets CONTAINARIUM_JWT_TOKEN_FILE pointing at its own
// 0600 token file, and the box principal is no longer copied into the run
// user's home. The run's platform MCP server (cmd/mcp-server: LoadConfig, then
// NewServer) must therefore take its credential from that file, on every
// request, and from nowhere else. This test builds the server the way
// cmd/mcp-server does, in the environment a run has, and reads the bearer
// token the control plane receives.
func TestRunEnvironment_MCPServerUsesThePerRunTokenFile(t *testing.T) {
	const perRunToken = "synthetic-per-run-token-3c7f.not-a-credential"
	const principal = "synthetic-box-principal-a41e.not-a-credential"

	var mu sync.Mutex
	var bearers []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		bearers = append(bearers, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"containers":[]}`))
	}))
	defer api.Close()

	// The run's token file, as the daemon installs it: 0600, the token and
	// nothing else.
	tokenFile := filepath.Join(t.TempDir(), "r1.token")
	if err := os.WriteFile(tokenFile, []byte(perRunToken), 0o600); err != nil {
		t.Fatal(err)
	}

	// A login left in the home directory (what a staged principal amounted to)
	// must not be what the run presents.
	writeCredsFile(t, t.TempDir(), api.URL, map[string]credentials.ServerCreds{api.URL: {Token: principal}})

	// The run's environment: the variable the daemon exports, and no static token.
	t.Setenv(config.EnvJWTTokenFile, tokenFile)
	t.Setenv(config.EnvJWTToken, "")
	t.Setenv("CONTAINARIUM_SERVER_URL", api.URL)

	cfg := LoadConfig()
	if cfg.JWTTokenFile != tokenFile || cfg.JWTToken != "" {
		t.Fatalf("config = token file %q, static token set: %v; want the per-run file only", cfg.JWTTokenFile, cfg.JWTToken != "")
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if _, err := srv.client.ListContainers(); err != nil {
		t.Fatalf("ListContainers: %v", err)
	}

	// The file is read per request: a token the daemon replaces (a later run
	// under the same name) is what the next request presents.
	const nextToken = "synthetic-per-run-token-next.not-a-credential"
	if err := os.WriteFile(tokenFile, []byte(nextToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.client.ListContainers(); err != nil {
		t.Fatalf("ListContainers after the token changed: %v", err)
	}

	seen := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bearers...)
	}
	want := []string{"Bearer " + perRunToken, "Bearer " + nextToken}
	got := seen()
	if len(got) != len(want) {
		t.Fatalf("the control plane saw %d request(s), want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("request %d presented %q, want the per-run token %q", i+1, got[i], want[i])
		}
	}

	// Once the run has ended the daemon removes the file. The server then
	// fails closed: it does not fall back to the login in the home directory.
	if err := os.Remove(tokenFile); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.client.ListContainers(); err == nil {
		t.Error("a request succeeded after the run's token file was removed")
	}
	if got := seen(); len(got) != len(want) {
		t.Errorf("a request reached the control plane without the per-run token: %v", got[len(want):])
	}
}
