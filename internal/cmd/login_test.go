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
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/credentials"
)

// withTempHome redirects $HOME so the credentials store writes
// under a tempdir for the test. Mirrors the helper in
// internal/credentials/store_test.go; duplicated here to keep this
// test file self-contained (the rule from Phase 1 is "don't modify
// shared test files"; "don't share helpers either" is the safe
// reading).
func withTempHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	// Reset the package-level flag globals between tests so a
	// previous test's --token / --server doesn't leak.
	t.Cleanup(func() {
		authToken = ""
		serverAddr = ""
		loginServer = ""
		whoamiServerFlag = ""
		configTokenSrv = ""
		logoutAll = false
		loginNoBrowser = false
		loginDeviceName = ""
	})
	return home
}

// seedCreds writes a credentials file with the supplied servers.
func seedCreds(t *testing.T, home string, defServer string, srvs map[string]credentials.ServerCreds) string {
	t.Helper()
	cf := credentials.NewCredentialsFile()
	for k, v := range srvs {
		cf.Set(k, v)
	}
	if defServer != "" {
		cf.DefaultServer = defServer
	}
	path := filepath.Join(home, credentials.DefaultRelPath)
	if err := credentials.Save(path, cf); err != nil {
		t.Fatalf("seed credentials: %v", err)
	}
	return path
}

func TestResolveAuthToken_PrecedenceChain(t *testing.T) {
	home := withTempHome(t)
	_ = seedCreds(t, home, "https://cloud.containarium.dev", map[string]credentials.ServerCreds{
		"https://cloud.containarium.dev":     {Token: "file-default"},
		"https://self-hosted.example.com":    {Token: "file-self"},
	})

	cases := []struct {
		name      string
		setAuth   string // simulate --token / env (already collapsed into authToken)
		setServer string
		want      string
	}{
		{
			name:    "flag wins",
			setAuth: "explicit-flag",
			want:    "explicit-flag",
		},
		{
			name: "no flag, no server -> default_server token",
			want: "file-default",
		},
		{
			name:      "no flag, server matches non-default",
			setServer: "https://self-hosted.example.com",
			want:      "file-self",
		},
		{
			name:      "no flag, server with trailing slash still matches",
			setServer: "https://self-hosted.example.com/",
			want:      "file-self",
		},
		{
			name:      "no flag, unknown server -> empty",
			setServer: "https://nope.example.com",
			want:      "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authToken = tc.setAuth
			serverAddr = tc.setServer
			defer func() { authToken = ""; serverAddr = "" }()
			got := resolveAuthToken(tc.setServer)
			if got != tc.want {
				t.Fatalf("resolveAuthToken = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveAuthToken_NoCredentialsFile(t *testing.T) {
	withTempHome(t)
	authToken = ""
	if got := resolveAuthToken(""); got != "" {
		t.Fatalf("resolveAuthToken with no file = %q, want empty", got)
	}
}

// fakeDeviceFlowServer runs an httptest server that mimics the
// cloud's CLISessionService just enough for the login command to
// drive a full happy-path. It returns "pending" for the first N
// status polls and "approved" thereafter.
type fakeDeviceFlowServer struct {
	srv          *httptest.Server
	approveAfter int32 // number of poll requests before flipping to approved
	pollCount    int32
	gotDevice    atomic.Value // string
}

func newFakeDeviceFlow(t *testing.T, approveAfter int32) *fakeDeviceFlowServer {
	t.Helper()
	f := &fakeDeviceFlowServer{approveAfter: approveAfter}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/cli/sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var req createSessionReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.gotDevice.Store(req.DeviceName)
		_ = json.NewEncoder(w).Encode(createSessionResp{
			SessionID:       "sess-1",
			UserCode:        "WXYZ-1234",
			VerificationURL: f.srv.URL + "/cli/authorize?code=WXYZ-1234",
			ExpiresIn:       600,
		})
	})
	mux.HandleFunc("/v1/cli/sessions/sess-1/status", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&f.pollCount, 1)
		resp := sessionStatusResp{Status: "pending"}
		if n > f.approveAfter {
			resp = sessionStatusResp{
				Status:    "approved",
				Token:     "ctnr_test_token",
				UserEmail: "alice@example.com",
				OrgID:     "org_42",
				ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func TestLogin_HappyPath_WritesCredentials(t *testing.T) {
	home := withTempHome(t)
	f := newFakeDeviceFlow(t, 1) // pending once, then approved
	loginServer = f.srv.URL
	loginNoBrowser = true

	// Run with a short poll interval so the test is fast.
	old := loginPollIntervalForTest()
	defer restorePollInterval(old)
	setPollInterval(20 * time.Millisecond)

	var out bytes.Buffer
	loginCmd.SetOut(&out)
	loginCmd.SetErr(&out)
	if err := runLogin(loginCmd, nil); err != nil {
		t.Fatalf("runLogin: %v", err)
	}

	// Credentials file written with the token.
	path := filepath.Join(home, credentials.DefaultRelPath)
	cf, err := credentials.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	creds, ok := cf.Get(f.srv.URL)
	if !ok {
		t.Fatalf("credentials not stored for %s; file: %+v", f.srv.URL, cf)
	}
	if creds.Token != "ctnr_test_token" {
		t.Fatalf("Token = %q, want ctnr_test_token", creds.Token)
	}
	if creds.UserEmail != "alice@example.com" {
		t.Fatalf("UserEmail = %q", creds.UserEmail)
	}
	if creds.OrgID != "org_42" {
		t.Fatalf("OrgID = %q", creds.OrgID)
	}
	if creds.IssuedAt.IsZero() {
		t.Fatal("IssuedAt not set")
	}
	if creds.ExpiresAt == nil {
		t.Fatal("ExpiresAt not parsed from RFC3339 response")
	}
	if cf.DefaultServer == "" {
		t.Fatal("DefaultServer not auto-set on first login")
	}

	// File mode 0600 (POSIX only).
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("file mode = %o, want 0600", st.Mode().Perm())
		}
	}

	// Output mentions the user code and the email.
	o := out.String()
	if !strings.Contains(o, "WXYZ-1234") {
		t.Errorf("output missing user code:\n%s", o)
	}
	if !strings.Contains(o, "alice@example.com") {
		t.Errorf("output missing user email:\n%s", o)
	}

	// Device name defaulted to non-empty.
	got := f.gotDevice.Load()
	if got == nil || got.(string) == "" {
		t.Errorf("device_name not sent in createSession request")
	}
}

func TestLogin_DeniedInBrowser_Errors(t *testing.T) {
	withTempHome(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/cli/sessions", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(createSessionResp{
			SessionID:       "sess-x",
			UserCode:        "DENIED",
			VerificationURL: "http://example.invalid/cli/authorize",
			ExpiresIn:       60,
		})
	})
	mux.HandleFunc("/v1/cli/sessions/sess-x/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(sessionStatusResp{Status: "denied"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	loginServer = srv.URL
	loginNoBrowser = true
	old := loginPollIntervalForTest()
	defer restorePollInterval(old)
	setPollInterval(10 * time.Millisecond)

	var out bytes.Buffer
	loginCmd.SetOut(&out)
	loginCmd.SetErr(&out)
	err := runLogin(loginCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected denied error, got %v", err)
	}
}

func TestLogout_RemovesServer(t *testing.T) {
	home := withTempHome(t)
	_ = seedCreds(t, home, "https://cloud.containarium.dev", map[string]credentials.ServerCreds{
		"https://cloud.containarium.dev":  {Token: "cloud-tok"},
		"https://self-hosted.example.com": {Token: "self-tok"},
	})

	loginServer = "https://self-hosted.example.com"
	logoutAll = false
	var out bytes.Buffer
	logoutCmd.SetOut(&out)
	if err := runLogout(logoutCmd, nil); err != nil {
		t.Fatalf("runLogout: %v", err)
	}
	cf, _ := credentials.Load(filepath.Join(home, credentials.DefaultRelPath))
	if _, ok := cf.Get("https://self-hosted.example.com"); ok {
		t.Fatal("self-hosted creds still present after logout")
	}
	if _, ok := cf.Get("https://cloud.containarium.dev"); !ok {
		t.Fatal("cloud creds wrongly removed by single-server logout")
	}
}

func TestLogout_All_WipesEverything(t *testing.T) {
	home := withTempHome(t)
	_ = seedCreds(t, home, "https://cloud.containarium.dev", map[string]credentials.ServerCreds{
		"https://cloud.containarium.dev":  {Token: "cloud-tok"},
		"https://self-hosted.example.com": {Token: "self-tok"},
	})

	loginServer = ""
	logoutAll = true
	var out bytes.Buffer
	logoutCmd.SetOut(&out)
	if err := runLogout(logoutCmd, nil); err != nil {
		t.Fatalf("runLogout --all: %v", err)
	}
	cf, _ := credentials.Load(filepath.Join(home, credentials.DefaultRelPath))
	if len(cf.Servers) != 0 {
		t.Fatalf("Servers = %+v, want empty", cf.Servers)
	}
	if cf.DefaultServer != "" {
		t.Fatalf("DefaultServer = %q, want empty", cf.DefaultServer)
	}
}

func TestLogout_NoDefault_NoServer_Errors(t *testing.T) {
	withTempHome(t)
	loginServer = ""
	logoutAll = false
	var out bytes.Buffer
	logoutCmd.SetOut(&out)
	err := runLogout(logoutCmd, nil)
	if err == nil {
		t.Fatal("expected error when no default and no --server")
	}
}

func TestWhoami_PrintsIdentity(t *testing.T) {
	home := withTempHome(t)
	exp := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	_ = seedCreds(t, home, "https://cloud.containarium.dev", map[string]credentials.ServerCreds{
		"https://cloud.containarium.dev": {
			Token: "tok", UserEmail: "alice@example.com", OrgID: "org_42",
			IssuedAt: time.Now().UTC(), ExpiresAt: &exp,
		},
	})
	whoamiServerFlag = ""
	var out bytes.Buffer
	whoamiCmd.SetOut(&out)
	if err := runWhoami(whoamiCmd, nil); err != nil {
		t.Fatalf("runWhoami: %v", err)
	}
	o := out.String()
	for _, want := range []string{"alice@example.com", "org_42", "cloud.containarium.dev", "2026-12-31"} {
		if !strings.Contains(o, want) {
			t.Errorf("whoami output missing %q:\n%s", want, o)
		}
	}
}

func TestWhoami_NoCredentials_Errors(t *testing.T) {
	withTempHome(t)
	whoamiServerFlag = ""
	var out bytes.Buffer
	whoamiCmd.SetOut(&out)
	if err := runWhoami(whoamiCmd, nil); err == nil {
		t.Fatal("expected error when no credentials present")
	}
}

func TestConfigGetToken_EmitsTokenNoNewline(t *testing.T) {
	home := withTempHome(t)
	_ = seedCreds(t, home, "https://cloud.containarium.dev", map[string]credentials.ServerCreds{
		"https://cloud.containarium.dev": {Token: "ctnr_pipeable"},
	})
	configTokenSrv = ""
	var out bytes.Buffer
	configGetTokenCmd.SetOut(&out)
	if err := runConfigGetToken(configGetTokenCmd, nil); err != nil {
		t.Fatalf("runConfigGetToken: %v", err)
	}
	got := out.String()
	if got != "ctnr_pipeable" {
		t.Fatalf("got %q, want %q (no trailing newline)", got, "ctnr_pipeable")
	}
}

func TestConfigGetToken_NoCreds_Errors(t *testing.T) {
	withTempHome(t)
	configTokenSrv = ""
	var out bytes.Buffer
	configGetTokenCmd.SetOut(&out)
	if err := runConfigGetToken(configGetTokenCmd, nil); err == nil {
		t.Fatal("expected error when no credentials")
	}
}

func TestNormalizeServer_LoginPathTrim(t *testing.T) {
	got := pickLoginServer("https://cloud.containarium.dev/")
	if got != "https://cloud.containarium.dev" {
		t.Fatalf("pickLoginServer = %q", got)
	}
	if d := pickLoginServer(""); d != defaultLoginServer {
		t.Fatalf("default = %q, want %q", d, defaultLoginServer)
	}
}

func TestDeviceName_FallbacksAreNonEmpty(t *testing.T) {
	if deviceName("explicit") != "explicit" {
		t.Fatal("explicit override not respected")
	}
	if deviceName("") == "" {
		t.Fatal("deviceName fallback returned empty string")
	}
}

// The poll-interval is a package-level const for production but we
// need to override it in tests so the device-flow test runs in
// milliseconds, not seconds. We swap the global via a mutator
// rather than threading a parameter through runLogin — it's only
// used here.

func setPollInterval(d time.Duration) { pollIntervalOverride = d }

func loginPollIntervalForTest() time.Duration { return pollIntervalOverride }

func restorePollInterval(d time.Duration) { pollIntervalOverride = d }
