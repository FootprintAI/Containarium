package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/credentials"
	"github.com/footprintai/containarium/internal/sshkey"
)

// withSSHHome mirrors withTempHome from login_test.go but also
// resets the ssh-command-scope flag globals between runs so
// previous tests' --name / --key don't leak.
func withSSHHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	t.Cleanup(func() {
		authToken = ""
		serverAddr = ""
		sshSetupName = ""
		sshSetupKeyPath = ""
		sshSetupGenerate = false
		sshSetupForce = false
		sshSetupServer = ""
		sshListServer = ""
		sshRemoveServer = ""
		sshPropagateServer = ""
		sshPropagateBoxes = nil
	})
	return home
}

func seedTokenFor(t *testing.T, home, server, token string) {
	t.Helper()
	cf := credentials.NewCredentialsFile()
	cf.Set(server, credentials.ServerCreds{
		Token:    token,
		IssuedAt: time.Now().UTC(),
	})
	path := filepath.Join(home, credentials.DefaultRelPath)
	if err := credentials.Save(path, cf); err != nil {
		t.Fatalf("seedTokenFor: %v", err)
	}
}

// fakeSSHKeysServer impersonates the cloud's UserService SSH-keys
// REST surface. We register only the routes the test needs and let
// the rest 404 (which the client turns into Unimplemented).
type fakeSSHKeysServer struct {
	srv     *httptest.Server
	mux     *http.ServeMux
	keys    []sshkey.SSHKey
	added   []addSSHKeyReq
	gotAuth string
}

func newFakeSSHKeysServer(t *testing.T) *fakeSSHKeysServer {
	t.Helper()
	f := &fakeSSHKeysServer{mux: http.NewServeMux()}
	f.srv = httptest.NewServer(f.mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSSHKeysServer) wireAdd() {
	f.mux.HandleFunc("/v1/user/ssh-keys", func(w http.ResponseWriter, r *http.Request) {
		f.gotAuth = r.Header.Get("Authorization")
		switch r.Method {
		case http.MethodPost:
			var req addSSHKeyReq
			_ = json.NewDecoder(r.Body).Decode(&req)
			f.added = append(f.added, req)
			fp, _ := sshkey.Fingerprint(req.PublicKey)
			k := sshkey.SSHKey{
				Name:        req.Name,
				PublicKey:   req.PublicKey,
				Fingerprint: fp,
				CreatedAt:   time.Now().UTC(),
			}
			f.keys = append(f.keys, k)
			_ = json.NewEncoder(w).Encode(addSSHKeyResp{Key: k})
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(listSSHKeysResp{Keys: f.keys})
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	})
}

func (f *fakeSSHKeysServer) wireRemove() {
	// Subtree handler — strip the prefix in the handler.
	f.mux.HandleFunc("/v1/user/ssh-keys/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/v1/user/ssh-keys/")
		out := f.keys[:0]
		for _, k := range f.keys {
			if k.Name != name {
				out = append(out, k)
			}
		}
		f.keys = out
		w.WriteHeader(http.StatusOK)
	})
}

// --- validators ---------------------------------------------------------

func TestValidateKeyName(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"plain", "alice", false},
		{"with at", "alice@laptop", false},
		{"with dash and underscore", "alice-mbp_2024", false},
		{"with dot", "alice.work", false},
		{"empty", "", true},
		{"whitespace only", "   ", true},
		{"too long", strings.Repeat("a", 65), true},
		{"path-traversal attempt", "../etc/passwd", true},
		{"slash", "alice/bob", true},
		{"space", "alice laptop", true},
		{"quote", `alice"laptop`, true},
		{"semicolon", "alice;rm", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateKeyName(tc.in)
			if tc.wantErr && err == nil {
				t.Errorf("validateKeyName(%q) = nil, want error", tc.in)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateKeyName(%q) = %v, want nil", tc.in, err)
			}
		})
	}
}

func TestValidateBoxName(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"plain", "alice", false},
		{"with dash", "ci-bob-pr123", false},
		{"empty", "", true},
		{"uppercase", "Alice", true},
		{"at sign", "alice@laptop", true},
		{"dot", "alice.laptop", true},
		{"too long", strings.Repeat("a", 33), true},
		{"slash", "alice/bob", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBoxName(tc.in)
			if tc.wantErr && err == nil {
				t.Errorf("validateBoxName(%q) = nil, want error", tc.in)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateBoxName(%q) = %v, want nil", tc.in, err)
			}
		})
	}
}

// --- pickSSHServer -----------------------------------------------------

func TestPickSSHServer_ExplicitWins(t *testing.T) {
	home := withSSHHome(t)
	seedTokenFor(t, home, "https://cloud.containarium.dev", "t")
	got := pickSSHServer("https://explicit.example.com/")
	if got != "https://explicit.example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestPickSSHServer_DefaultsToCredentials(t *testing.T) {
	home := withSSHHome(t)
	seedTokenFor(t, home, "https://self-hosted.example.com", "t")
	got := pickSSHServer("")
	if got != "https://self-hosted.example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestPickSSHServer_FallsBackToConstant(t *testing.T) {
	withSSHHome(t)
	got := pickSSHServer("")
	if got != defaultLoginServer {
		t.Fatalf("got %q, want %q", got, defaultLoginServer)
	}
}

// --- newSSHHTTPClient ---------------------------------------------------

func TestNewSSHHTTPClient_RequiresToken(t *testing.T) {
	withSSHHome(t)
	_, err := newSSHHTTPClient("https://no-token.example.com")
	if err == nil || !strings.Contains(err.Error(), "no auth token") {
		t.Fatalf("err = %v, want no-auth-token error", err)
	}
}

func TestNewSSHHTTPClient_LoadsTokenFromCreds(t *testing.T) {
	home := withSSHHome(t)
	seedTokenFor(t, home, "https://cloud.example.com", "tok-xyz")
	c, err := newSSHHTTPClient("https://cloud.example.com")
	if err != nil {
		t.Fatalf("newSSHHTTPClient: %v", err)
	}
	if c.token != "tok-xyz" {
		t.Errorf("token = %q", c.token)
	}
}

// --- runSSHSetup --------------------------------------------------------

func TestSSHSetup_HappyPath_GeneratesAndUploads(t *testing.T) {
	home := withSSHHome(t)
	f := newFakeSSHKeysServer(t)
	f.wireAdd()
	seedTokenFor(t, home, f.srv.URL, "tok")

	sshSetupServer = f.srv.URL
	sshSetupName = "alice-laptop"

	var out bytes.Buffer
	sshSetupCmd.SetOut(&out)
	sshSetupCmd.SetErr(&out)
	if err := runSSHSetup(sshSetupCmd, nil); err != nil {
		t.Fatalf("runSSHSetup: %v", err)
	}

	if len(f.added) != 1 {
		t.Fatalf("added = %+v, want 1 entry", f.added)
	}
	if f.added[0].Name != "alice-laptop" {
		t.Errorf("Name = %q", f.added[0].Name)
	}
	if !strings.HasPrefix(f.added[0].PublicKey, "ssh-ed25519 ") {
		t.Errorf("PublicKey = %q, want ssh-ed25519 prefix", f.added[0].PublicKey)
	}
	if !strings.HasPrefix(f.gotAuth, "Bearer tok") {
		t.Errorf("Authorization header = %q", f.gotAuth)
	}

	o := out.String()
	if !strings.Contains(o, "Generated new ed25519 keypair") {
		t.Errorf("output missing generation notice:\n%s", o)
	}
	if !strings.Contains(o, "Registered key") {
		t.Errorf("output missing success line:\n%s", o)
	}

	// Key file actually landed in $HOME/.ssh.
	if _, err := os.Stat(filepath.Join(home, ".ssh", "containarium_ed25519.pub")); err != nil {
		t.Errorf("public key not on disk: %v", err)
	}
}

func TestSSHSetup_UsesExplicitKeyFlag(t *testing.T) {
	home := withSSHHome(t)

	// Generate a key into a sidecar dir, then point --key at it.
	stage := t.TempDir()
	_, pub, err := sshkey.Generate(sshkey.LocateOpts{HomeDir: stage}, false)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	keyPath := filepath.Join(stage, ".ssh", "containarium_ed25519.pub")

	f := newFakeSSHKeysServer(t)
	f.wireAdd()
	seedTokenFor(t, home, f.srv.URL, "tok")

	sshSetupServer = f.srv.URL
	sshSetupKeyPath = keyPath

	var out bytes.Buffer
	sshSetupCmd.SetOut(&out)
	if err := runSSHSetup(sshSetupCmd, nil); err != nil {
		t.Fatalf("runSSHSetup: %v", err)
	}
	if len(f.added) != 1 {
		t.Fatalf("added = %+v", f.added)
	}
	if strings.TrimSpace(f.added[0].PublicKey) != pub {
		t.Errorf("uploaded pubkey doesn't match --key file")
	}

	// We did NOT generate anything in $HOME/.ssh.
	if _, err := os.Stat(filepath.Join(home, ".ssh", "containarium_ed25519.pub")); err == nil {
		t.Error("setup unexpectedly generated a key in HOME when --key was given")
	}
}

func TestSSHSetup_BadNameRejected(t *testing.T) {
	home := withSSHHome(t)
	f := newFakeSSHKeysServer(t)
	f.wireAdd()
	seedTokenFor(t, home, f.srv.URL, "tok")

	sshSetupServer = f.srv.URL
	sshSetupName = "alice; rm -rf /"

	var out bytes.Buffer
	sshSetupCmd.SetOut(&out)
	err := runSSHSetup(sshSetupCmd, nil)
	if err == nil {
		t.Fatal("expected error on disallowed name")
	}
	if len(f.added) != 0 {
		t.Errorf("bad name reached server: %+v", f.added)
	}
}

func TestSSHSetup_NoToken_Errors(t *testing.T) {
	withSSHHome(t)
	f := newFakeSSHKeysServer(t)
	f.wireAdd()
	// Note: no seedTokenFor — credentials file is empty.

	sshSetupServer = f.srv.URL
	sshSetupName = "alice"

	var out bytes.Buffer
	sshSetupCmd.SetOut(&out)
	err := runSSHSetup(sshSetupCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "no auth token") {
		t.Fatalf("err = %v, want no-auth-token", err)
	}
}

func TestSSHSetup_GracefulOnUnimplementedServer(t *testing.T) {
	home := withSSHHome(t)
	// Empty mux → every route 404s → client maps to Unimplemented.
	f := newFakeSSHKeysServer(t)
	seedTokenFor(t, home, f.srv.URL, "tok")

	sshSetupServer = f.srv.URL
	sshSetupName = "alice"

	var out bytes.Buffer
	sshSetupCmd.SetOut(&out)
	if err := runSSHSetup(sshSetupCmd, nil); err != nil {
		t.Fatalf("runSSHSetup should swallow Unimplemented, got: %v", err)
	}
	o := out.String()
	if !strings.Contains(o, "not yet supported") {
		t.Errorf("expected friendly warning in output:\n%s", o)
	}
}

// --- runSSHList ---------------------------------------------------------

func TestSSHList_EmptyPrintsHint(t *testing.T) {
	home := withSSHHome(t)
	f := newFakeSSHKeysServer(t)
	f.wireAdd()
	seedTokenFor(t, home, f.srv.URL, "tok")

	sshListServer = f.srv.URL
	var out bytes.Buffer
	sshListCmd.SetOut(&out)
	if err := runSSHList(sshListCmd, nil); err != nil {
		t.Fatalf("runSSHList: %v", err)
	}
	if !strings.Contains(out.String(), "No SSH keys registered") {
		t.Errorf("expected empty-hint output, got %q", out.String())
	}
}

func TestSSHList_PrintsTable(t *testing.T) {
	home := withSSHHome(t)
	f := newFakeSSHKeysServer(t)
	f.wireAdd()
	seedTokenFor(t, home, f.srv.URL, "tok")

	// Seed two keys by hitting setup twice with different names.
	for _, n := range []string{"alice-laptop", "alice-mbp"} {
		sshSetupServer = f.srv.URL
		sshSetupName = n
		sshSetupGenerate = true
		sshSetupForce = true
		var sink bytes.Buffer
		sshSetupCmd.SetOut(&sink)
		if err := runSSHSetup(sshSetupCmd, nil); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	sshSetupName = ""
	sshSetupGenerate = false
	sshSetupForce = false

	sshListServer = f.srv.URL
	var out bytes.Buffer
	sshListCmd.SetOut(&out)
	if err := runSSHList(sshListCmd, nil); err != nil {
		t.Fatalf("runSSHList: %v", err)
	}
	o := out.String()
	for _, want := range []string{"NAME", "FINGERPRINT", "alice-laptop", "alice-mbp", "SHA256:"} {
		if !strings.Contains(o, want) {
			t.Errorf("output missing %q:\n%s", want, o)
		}
	}
}

func TestSSHList_GracefulOnUnimplemented(t *testing.T) {
	home := withSSHHome(t)
	f := newFakeSSHKeysServer(t)
	seedTokenFor(t, home, f.srv.URL, "tok")

	sshListServer = f.srv.URL
	var out bytes.Buffer
	sshListCmd.SetOut(&out)
	if err := runSSHList(sshListCmd, nil); err != nil {
		t.Fatalf("runSSHList: %v", err)
	}
	if !strings.Contains(out.String(), "not yet supported") {
		t.Errorf("expected warning output, got %q", out.String())
	}
}

// --- runSSHRemove -------------------------------------------------------

func TestSSHRemove_HappyPath(t *testing.T) {
	home := withSSHHome(t)
	f := newFakeSSHKeysServer(t)
	f.wireAdd()
	f.wireRemove()
	seedTokenFor(t, home, f.srv.URL, "tok")

	sshSetupServer = f.srv.URL
	sshSetupName = "alice-laptop"
	var sink bytes.Buffer
	sshSetupCmd.SetOut(&sink)
	if err := runSSHSetup(sshSetupCmd, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sshSetupName = ""

	sshRemoveServer = f.srv.URL
	var out bytes.Buffer
	sshRemoveCmd.SetOut(&out)
	if err := runSSHRemove(sshRemoveCmd, []string{"alice-laptop"}); err != nil {
		t.Fatalf("runSSHRemove: %v", err)
	}
	if len(f.keys) != 0 {
		t.Errorf("keys = %+v, want empty after remove", f.keys)
	}
	if !strings.Contains(out.String(), "Removed SSH key") {
		t.Errorf("output: %q", out.String())
	}
}

func TestSSHRemove_BadNameRejected(t *testing.T) {
	home := withSSHHome(t)
	f := newFakeSSHKeysServer(t)
	seedTokenFor(t, home, f.srv.URL, "tok")
	sshRemoveServer = f.srv.URL

	err := runSSHRemove(sshRemoveCmd, []string{"../etc/shadow"})
	if err == nil {
		t.Fatal("expected error on disallowed name")
	}
}

// --- runSSHPropagate ----------------------------------------------------

func TestSSHPropagate_GracefulOnUnimplemented(t *testing.T) {
	home := withSSHHome(t)
	f := newFakeSSHKeysServer(t)
	seedTokenFor(t, home, f.srv.URL, "tok")

	sshPropagateServer = f.srv.URL
	var out bytes.Buffer
	sshPropagateCmd.SetOut(&out)
	if err := runSSHPropagate(sshPropagateCmd, nil); err != nil {
		t.Fatalf("runSSHPropagate should swallow Unimplemented, got: %v", err)
	}
	o := out.String()
	if !strings.Contains(o, "not yet supported") {
		t.Errorf("expected friendly warning, got %q", o)
	}
}

func TestSSHPropagate_HappyPath(t *testing.T) {
	home := withSSHHome(t)
	f := newFakeSSHKeysServer(t)
	f.mux.HandleFunc("/v1/user/ssh-keys:propagate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var req propagateReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		boxes := req.Boxes
		if len(boxes) == 0 {
			boxes = []string{"alice", "bob"}
		}
		_ = json.NewEncoder(w).Encode(propagateResp{UpdatedBoxes: boxes})
	})
	seedTokenFor(t, home, f.srv.URL, "tok")

	sshPropagateServer = f.srv.URL
	sshPropagateBoxes = []string{"alice", "ci-box-1"}
	var out bytes.Buffer
	sshPropagateCmd.SetOut(&out)
	if err := runSSHPropagate(sshPropagateCmd, nil); err != nil {
		t.Fatalf("runSSHPropagate: %v", err)
	}
	o := out.String()
	for _, want := range []string{"Updated 2 box(es)", "+ alice", "+ ci-box-1"} {
		if !strings.Contains(o, want) {
			t.Errorf("output missing %q:\n%s", want, o)
		}
	}
}

func TestSSHPropagate_RejectsBadBoxName(t *testing.T) {
	home := withSSHHome(t)
	f := newFakeSSHKeysServer(t)
	seedTokenFor(t, home, f.srv.URL, "tok")

	sshPropagateServer = f.srv.URL
	sshPropagateBoxes = []string{"alice", "alice@laptop"}
	var out bytes.Buffer
	sshPropagateCmd.SetOut(&out)
	err := runSSHPropagate(sshPropagateCmd, nil)
	if err == nil {
		t.Fatal("expected error on disallowed box name")
	}
}
