package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/credentials"
	"github.com/footprintai/containarium/internal/sshkey"
)

// Tests for sub-task A7 (umbrella-issue #100): the
// `containarium login --with-ssh-setup / --no-ssh-setup` integration
// landed in login.go's runLogin tail-call to maybeRunPostLoginSSHSetup.
//
// These tests intentionally live in a NEW file (per the brief's
// "lesson from Phase 1: don't modify shared test files"). They share
// the cmd-package globals with ssh_test.go and login_test.go but
// redeclare nothing — withSSHHome (defined in ssh_test.go) is reused
// because its cleanup already resets the ssh-setup-related flag
// globals.

// withSSHLoginHome stacks ssh_test.go's withSSHHome with extra
// cleanup for the A7-only flag globals (loginWithSSHSetup,
// loginNoSSHSetup, loginPromptReader).
func withSSHLoginHome(t *testing.T) string {
	t.Helper()
	home := withSSHHome(t)
	t.Cleanup(func() {
		loginWithSSHSetup = false
		loginNoSSHSetup = false
		loginPromptReader = nil
		loginServer = ""
		loginNoBrowser = false
		loginDeviceName = ""
	})
	return home
}

// fakeLoginAndSSHKeysServer wires the device-flow endpoints from
// login.go AND the SSH-keys endpoints from ssh.go on a single
// httptest.Server, because the post-login auto-setup path expects to
// hit the same host the login ran against.
type fakeLoginAndSSHKeysServer struct {
	srv           *httptest.Server
	addedKeys     []addSSHKeyReq
	approveAfter  int32
	pollCount     int32
	sawAddSSHKey  atomic.Bool
	receivedToken string
}

func newFakeLoginAndSSHKeysServer(t *testing.T, approveAfter int32) *fakeLoginAndSSHKeysServer {
	t.Helper()
	mux := http.NewServeMux()
	f := &fakeLoginAndSSHKeysServer{approveAfter: approveAfter}

	mux.HandleFunc("/v1/cli/sessions", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(createSessionResp{
			SessionID:       "sess-A7",
			UserCode:        "WXYZ-7777",
			VerificationURL: "http://example.invalid/cli/authorize",
			ExpiresIn:       600,
		})
	})
	mux.HandleFunc("/v1/cli/sessions/sess-A7/status", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&f.pollCount, 1)
		resp := sessionStatusResp{Status: "pending"}
		if n > f.approveAfter {
			resp = sessionStatusResp{
				Status:    "approved",
				Token:     "tok-A7",
				UserEmail: "alice@example.com",
				OrgID:     "org_42",
				ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// SSH-key Add endpoint. Records the bearer token so the test can
	// assert the login → ssh-setup handoff used the freshly-issued
	// credential.
	mux.HandleFunc("/v1/user/ssh-keys", func(w http.ResponseWriter, r *http.Request) {
		f.receivedToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.sawAddSSHKey.Store(true)
		var req addSSHKeyReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.addedKeys = append(f.addedKeys, req)
		fp, _ := sshkey.Fingerprint(req.PublicKey)
		_ = json.NewEncoder(w).Encode(addSSHKeyResp{
			Key: sshkey.SSHKey{
				Name:        req.Name,
				PublicKey:   req.PublicKey,
				Fingerprint: fp,
				CreatedAt:   time.Now().UTC(),
			},
		})
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// runLoginWithSSHFlagsHelper performs the common test-setup boilerplate
// for the A7 cases: short poll interval, no browser, scripted stdin.
func runLoginWithSSHFlagsHelper(t *testing.T, f *fakeLoginAndSSHKeysServer, promptInput string) (*bytes.Buffer, error) {
	t.Helper()
	loginServer = f.srv.URL
	loginNoBrowser = true
	loginPromptReader = strings.NewReader(promptInput)

	old := loginPollIntervalForTest()
	t.Cleanup(func() { restorePollInterval(old) })
	setPollInterval(10 * time.Millisecond)

	var out bytes.Buffer
	loginCmd.SetOut(&out)
	loginCmd.SetErr(&out)
	err := runLogin(loginCmd, nil)
	return &out, err
}

func TestLogin_NoSSHSetup_SkipsRegistration(t *testing.T) {
	withSSHLoginHome(t)
	f := newFakeLoginAndSSHKeysServer(t, 0)

	loginNoSSHSetup = true
	out, err := runLoginWithSSHFlagsHelper(t, f, "")
	if err != nil {
		t.Fatalf("runLogin: %v", err)
	}

	if f.sawAddSSHKey.Load() {
		t.Errorf("--no-ssh-setup should have skipped AddSSHKey, but it was called")
	}
	// Login itself succeeded — credentials file written.
	path, _ := credentials.DefaultPath()
	cf, _ := credentials.Load(path)
	if _, ok := cf.Get(f.srv.URL); !ok {
		t.Errorf("login credentials missing after --no-ssh-setup login")
	}
	o := out.String()
	if !strings.Contains(o, "Logged in as alice@example.com") {
		t.Errorf("login success line missing:\n%s", o)
	}
	if strings.Contains(o, "Register this machine's SSH key") {
		t.Errorf("--no-ssh-setup leaked the prompt:\n%s", o)
	}
}

func TestLogin_WithSSHSetup_AutoRegisters(t *testing.T) {
	withSSHLoginHome(t)
	f := newFakeLoginAndSSHKeysServer(t, 0)

	loginWithSSHSetup = true
	loginDeviceName = "alice-laptop"
	out, err := runLoginWithSSHFlagsHelper(t, f, "")
	if err != nil {
		t.Fatalf("runLogin: %v", err)
	}

	if !f.sawAddSSHKey.Load() {
		t.Fatalf("--with-ssh-setup should have triggered AddSSHKey; output:\n%s", out.String())
	}
	if f.receivedToken != "tok-A7" {
		t.Errorf("AddSSHKey called with token %q, want tok-A7", f.receivedToken)
	}
	if len(f.addedKeys) != 1 {
		t.Fatalf("added = %+v, want 1 entry", f.addedKeys)
	}
	if f.addedKeys[0].Name != "alice-laptop" {
		t.Errorf("registered key name = %q, want alice-laptop (from --device-name)", f.addedKeys[0].Name)
	}
}

func TestLogin_PromptYDefault_RegistersOnEmptyInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("interactive prompt behaviour is POSIX-only in this test")
	}
	withSSHLoginHome(t)
	f := newFakeLoginAndSSHKeysServer(t, 0)

	// Empty line = accept Y default.
	out, err := runLoginWithSSHFlagsHelper(t, f, "\n")
	if err != nil {
		t.Fatalf("runLogin: %v", err)
	}
	if !f.sawAddSSHKey.Load() {
		t.Fatalf("empty answer (Y default) should trigger AddSSHKey; output:\n%s", out.String())
	}
}

func TestLogin_PromptN_SkipsRegistration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("interactive prompt behaviour is POSIX-only in this test")
	}
	withSSHLoginHome(t)
	f := newFakeLoginAndSSHKeysServer(t, 0)

	out, err := runLoginWithSSHFlagsHelper(t, f, "n\n")
	if err != nil {
		t.Fatalf("runLogin: %v", err)
	}
	if f.sawAddSSHKey.Load() {
		t.Errorf("answer 'n' should NOT trigger AddSSHKey; output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "skipped") {
		t.Errorf("expected skip notice in output:\n%s", out.String())
	}
}

func TestReadYesNo_Defaults(t *testing.T) {
	cases := []struct {
		name string
		in   string
		yes  bool
		ok   bool
	}{
		{"empty line treated as yes", "\n", true, true},
		{"y", "y\n", true, true},
		{"Y", "Y\n", true, true},
		{"yes", "yes\n", true, true},
		{"n", "n\n", false, true},
		{"N", "N\n", false, true},
		{"no", "no\n", false, true},
		{"unknown text parsed as no", "maybe\n", false, true},
		{"EOF (no newline) is unknown", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yes, ok := readYesNo(strings.NewReader(tc.in))
			if yes != tc.yes || ok != tc.ok {
				t.Errorf("readYesNo(%q) = (%v, %v), want (%v, %v)", tc.in, yes, ok, tc.yes, tc.ok)
			}
		})
	}
}
