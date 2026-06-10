package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
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
		"https://cloud.containarium.dev":  {Token: "file-default"},
		"https://self-hosted.example.com": {Token: "file-self"},
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

// TestCreateSession_DecodesCloudCamelCaseWire pins the POST /v1/cli/sessions
// WIRE contract with HAND-WRITTEN lowerCamelCase JSON (captured from the live
// cloud's grpc-gateway output) — NOT marshaled from createSessionResp. The
// fakeDeviceFlowServer round-trips the struct, so it can't catch a tag drift;
// this can. An earlier snake_case version of the struct decoded this body to
// all-zero and login failed with "incomplete session".
func TestCreateSession_DecodesCloudCamelCaseWire(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sessionId":"sess-1","userCode":"WXYZ-1234",` +
			`"verificationUrl":"https://cloud.example/cli/authorize?code=WXYZ-1234",` +
			`"expiresInSeconds":600,"pollingIntervalSeconds":5,"expiresAt":"2026-06-03T08:43:25Z"}`))
	}))
	defer srv.Close()

	got, err := createSession(context.Background(), srv.Client(), srv.URL, "cloud-mcp")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	if got.SessionID != "sess-1" || got.UserCode != "WXYZ-1234" {
		t.Errorf("sessionId/userCode not decoded: %+v", got)
	}
	if got.VerificationURL == "" {
		t.Error("verificationUrl not decoded (would trip the incomplete-session guard)")
	}
	if got.ExpiresIn != 600 {
		t.Errorf("expiresInSeconds = %d, want 600", got.ExpiresIn)
	}
}

// TestFetchSessionStatus_NormalizesProtoEnum pins two wire facts: (1) the
// cloud emits CLISessionStatus as the proto-enum NAME
// ("CLI_SESSION_STATUS_APPROVED"), which the handler folds to the short token
// the poll loop switches on; (2) the status response carries NO email/org —
// the cloud's GetCLISessionStatusResponse has only status/token/expires_at/
// approved_at, so identity rides the token, not these fields.
func TestFetchSessionStatus_NormalizesProtoEnum(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"CLI_SESSION_STATUS_APPROVED","token":"ctnr_test",` +
			`"expiresAt":"2026-06-03T08:53:30Z"}`))
	}))
	defer srv.Close()

	st, err := fetchSessionStatus(context.Background(), srv.Client(), srv.URL+"/status")
	if err != nil {
		t.Fatalf("fetchSessionStatus: %v", err)
	}
	if st.Status != "approved" {
		t.Errorf("Status = %q, want normalized %q", st.Status, "approved")
	}
	if st.Token != "ctnr_test" {
		t.Errorf("Token = %q, want ctnr_test", st.Token)
	}
	if st.UserEmail != "" || st.OrgID != "" {
		t.Errorf("email/org must be empty (cloud status response omits them): email=%q org=%q", st.UserEmail, st.OrgID)
	}
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

// TestDeviceName_DefaultIsAutoDisambiguated guards the #456 fix: the
// default device name carries a per-login suffix so repeat logins from
// one host don't collide with a still-live token of the same name.
func TestDeviceName_DefaultIsAutoDisambiguated(t *testing.T) {
	// Explicit override is verbatim — no suffix, byte-for-byte.
	if got := deviceName("cloud-mcp"); got != "cloud-mcp" {
		t.Fatalf("explicit override mutated: %q", got)
	}

	// The default name starts with the sanitized "<user>@<host>" base
	// (charset-conformed for the cloud, #634) and appends "-<suffix>".
	base := sanitizeDeviceLabel(defaultDeviceBase())
	a := deviceName("")
	if !strings.HasPrefix(a, base+"-") {
		t.Fatalf("default %q should start with base %q + '-'", a, base)
	}

	// Two successive default names must differ (collision-avoidance is
	// the whole point) and only in the suffix.
	b := deviceName("")
	if a == b {
		t.Fatalf("two default device names collided: %q == %q", a, b)
	}
	for _, n := range []string{a, b} {
		suffix := strings.TrimPrefix(n, base+"-")
		if len(suffix) != 6 {
			t.Errorf("suffix %q (from %q) is not 6 chars", suffix, n)
		}
	}
}

// cloudDeviceNameRe mirrors the cloud's device_name validation
// (#634): 1-64 chars of [-_.() a-zA-Z0-9].
var cloudDeviceNameRe = regexp.MustCompile(`^[-_.() a-zA-Z0-9]{1,64}$`)

// TestDeviceName_DefaultMatchesCloudCharset guards #634: the auto-generated
// default must satisfy the cloud's device_name validation with no user
// action — the old "<user>@<host>" default carried '@' and 400'd every login.
func TestDeviceName_DefaultMatchesCloudCharset(t *testing.T) {
	got := deviceName("")
	if !cloudDeviceNameRe.MatchString(got) {
		t.Errorf("default device name %q does not match cloud charset %s", got, cloudDeviceNameRe)
	}
	if strings.Contains(got, "@") {
		t.Errorf("default device name %q still contains '@'", got)
	}
}

func TestDefaultDeviceName_SanitizesAndClamps(t *testing.T) {
	// '@' (user@host) and '\' (Windows DOMAIN\user) map to '-'.
	if got := defaultDeviceName("alice@laptop.local", "abc123"); got != "alice-laptop.local-abc123" {
		t.Errorf("sanitize @ : got %q", got)
	}
	if got := defaultDeviceName(`CORP\bob`, "abc123"); got != "CORP-bob-abc123" {
		t.Errorf("sanitize backslash: got %q", got)
	}
	// Over-long base is clamped so "<base>-<suffix>" fits 64 chars, suffix kept.
	long := defaultDeviceName(strings.Repeat("x", 200), "abc123")
	if len(long) > allowedDeviceNameLen {
		t.Errorf("clamped name %q exceeds %d chars (len %d)", long, allowedDeviceNameLen, len(long))
	}
	if !strings.HasSuffix(long, "-abc123") {
		t.Errorf("clamp dropped the suffix: %q", long)
	}
	if !cloudDeviceNameRe.MatchString(long) {
		t.Errorf("clamped name %q violates cloud charset", long)
	}
	// An all-disallowed base trims to empty → fall back to the bare suffix
	// (still a valid, non-empty device name).
	if got := defaultDeviceName("@@@", "abc123"); got != "abc123" {
		t.Errorf("all-disallowed base: got %q, want bare suffix", got)
	}
}

func TestShortDeviceSuffix_HexAndVaries(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		s := shortDeviceSuffix()
		if len(s) != 6 {
			t.Fatalf("suffix %q not 6 chars", s)
		}
		if _, err := hex.DecodeString(s); err != nil {
			t.Fatalf("suffix %q not hex: %v", s, err)
		}
		seen[s] = true
	}
	// 100 draws from 24 bits should essentially never all collide.
	if len(seen) < 90 {
		t.Errorf("suffix not varying enough: %d unique of 100", len(seen))
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

// --- #455: pollSession transient-error resilience ---

// statusServer stands up a programmable /status endpoint. handler is
// invoked with the 1-based poll count so a test can vary the reply by
// attempt (e.g. "fail 3 times, then approve"). Returns the server and a
// pointer to the live poll counter.
func statusServer(t *testing.T, sessionID string, handler func(n int32, w http.ResponseWriter)) (*httptest.Server, *int32) {
	t.Helper()
	var n int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/cli/sessions/"+sessionID+"/status", func(w http.ResponseWriter, r *http.Request) {
		handler(atomic.AddInt32(&n, 1), w)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &n
}

// TestPollSession_RidesTransientErrors is the core #455 regression: a
// 5xx on the first polls must NOT abort the login. Pre-fix, pollSession
// returned on poll #1; now it rides through and succeeds once the
// server recovers.
func TestPollSession_RidesTransientErrors(t *testing.T) {
	srv, _ := statusServer(t, "sess-1", func(n int32, w http.ResponseWriter) {
		if n <= 3 {
			http.Error(w, "upstream hiccup", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(sessionStatusResp{Status: "approved", Token: "ctnr_ok"})
	})
	var out bytes.Buffer
	st, err := pollSession(context.Background(), &out, srv.Client(), srv.URL, "sess-1", time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("pollSession should ride out transient 5xx then approve, got err: %v", err)
	}
	if st.Token != "ctnr_ok" {
		t.Fatalf("Token = %q, want ctnr_ok", st.Token)
	}
	if !strings.Contains(out.String(), "retrying") {
		t.Errorf("expected a transient-retry notice in output, got:\n%s", out.String())
	}
}

// TestPollSession_GivesUpAfterConsecutiveFailures: a server that's down
// for good must fail fast at the consecutive cap, not silently retry
// the entire maxWait window.
func TestPollSession_GivesUpAfterConsecutiveFailures(t *testing.T) {
	srv, n := statusServer(t, "sess-1", func(_ int32, w http.ResponseWriter) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	})
	_, err := pollSession(context.Background(), nil, srv.Client(), srv.URL, "sess-1", time.Millisecond, 30*time.Second)
	if err == nil || !strings.Contains(err.Error(), "consecutive failures") {
		t.Fatalf("want consecutive-failures error, got %v", err)
	}
	if got := atomic.LoadInt32(n); got != int32(maxConsecutivePollFailures) {
		t.Errorf("polled %d times, want exactly %d (the cap)", got, maxConsecutivePollFailures)
	}
}

// TestPollSession_SessionGoneIsTerminal: a 404 is terminal — stop at
// once (surfaced as the expired message), never retry.
func TestPollSession_SessionGoneIsTerminal(t *testing.T) {
	srv, n := statusServer(t, "sess-1", func(_ int32, w http.ResponseWriter) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := pollSession(context.Background(), nil, srv.Client(), srv.URL, "sess-1", time.Millisecond, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "expired before approval") {
		t.Fatalf("want terminal expired error, got %v", err)
	}
	if got := atomic.LoadInt32(n); got != 1 {
		t.Errorf("polled %d times on a 404, want exactly 1 (no retry)", got)
	}
}

// TestPollSession_TimeoutWrapsSentinel: a forever-pending session over
// a tiny window returns errPollTimeout, so runLogin can distinguish a
// timeout (→ #456 guidance) from other failures.
func TestPollSession_TimeoutWrapsSentinel(t *testing.T) {
	srv, _ := statusServer(t, "sess-1", func(_ int32, w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(sessionStatusResp{Status: "pending"})
	})
	_, err := pollSession(context.Background(), nil, srv.Client(), srv.URL, "sess-1", 5*time.Millisecond, 25*time.Millisecond)
	if !errors.Is(err, errPollTimeout) {
		t.Fatalf("want errPollTimeout, got %v", err)
	}
}

// --- #456: actionable guidance on the timeout path ---

// TestLogin_Timeout_PrintsCollisionGuidance: when approval never lands
// (the device-name-collision symptom), runLogin must point the user at
// the remedy — revoke the old token or pick a different --device-name —
// instead of leaving a bare timeout.
func TestLogin_Timeout_PrintsCollisionGuidance(t *testing.T) {
	withTempHome(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/cli/sessions", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(createSessionResp{
			SessionID:       "sess-1",
			UserCode:        "WXYZ-1234",
			VerificationURL: "http://example.invalid/cli/authorize?code=WXYZ-1234",
			ExpiresIn:       600,
		})
	})
	mux.HandleFunc("/v1/cli/sessions/sess-1/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(sessionStatusResp{Status: "pending"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	loginServer = srv.URL
	loginNoBrowser = true
	loginDeviceName = "cloud-mcp"

	oldPoll, oldWait := pollIntervalOverride, maxWaitOverride
	defer func() { pollIntervalOverride = oldPoll; maxWaitOverride = oldWait; loginDeviceName = "" }()
	pollIntervalOverride = 5 * time.Millisecond
	maxWaitOverride = 25 * time.Millisecond

	var out bytes.Buffer
	loginCmd.SetOut(&out)
	loginCmd.SetErr(&out)
	err := runLogin(loginCmd, nil)
	if !errors.Is(err, errPollTimeout) {
		t.Fatalf("want errPollTimeout from runLogin, got %v", err)
	}
	o := out.String()
	for _, want := range []string{"already be in use", "cloud-mcp", "--device-name", "/settings/api-tokens"} {
		if !strings.Contains(o, want) {
			t.Errorf("timeout guidance missing %q:\n%s", want, o)
		}
	}
}
