package sentinel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
)

const fail2banAdminSecret = "abcdefghijklmnopqrstuvwxyz0123456789ABCD" // 41 bytes

// fakeFail2BanRunner is a scripted Fail2BanRunner (#1962) — lets the
// handler tests below exercise every branch of the fail2ban-client
// output parsing and error classification without a real fail2ban
// install, which most dev sandboxes and CI runners don't have.
// Responses are keyed by the joined args of the exact call expected;
// an unscripted call fails loudly instead of silently returning "".
type fakeFail2BanRunner struct {
	mu        sync.Mutex
	responses map[string]fakeFail2BanResponse
	calls     []string
}

type fakeFail2BanResponse struct {
	output string
	err    error
}

func newFakeFail2BanRunner() *fakeFail2BanRunner {
	return &fakeFail2BanRunner{responses: map[string]fakeFail2BanResponse{}}
}

func (f *fakeFail2BanRunner) on(resp fakeFail2BanResponse, args ...string) {
	f.responses[strings.Join(args, " ")] = resp
}

func (f *fakeFail2BanRunner) Run(args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Join(args, " ")
	f.calls = append(f.calls, key)
	resp, ok := f.responses[key]
	if !ok {
		return "", fmt.Errorf("fakeFail2BanRunner: unscripted call: fail2ban-client %s", key)
	}
	return resp.output, resp.err
}

func (f *fakeFail2BanRunner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func newManagerForFail2BanTest(t *testing.T, runner Fail2BanRunner) *Manager {
	t.Helper()
	m := &Manager{backends: NewBackendPool()}
	m.SetAdminSecret([]byte(fail2banAdminSecret))
	m.SetFail2BanRunner(runner)
	return m
}

func signedGet(path, secret string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	auth.SignSentinelRequest(req, []byte(secret))
	return req
}

func signedPost(t *testing.T, path, secret string, body any) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(secret))
	return req
}

// ---- GET /sentinel/fail2ban/bans ----------------------------------

// TestFail2BanBansHandler_MultipleJailsSomeBannedSomeNot is the bans-
// listing happy path (#1962 acceptance criterion 1): jails are
// discovered dynamically (never hardcoded), and each jail's response
// carries BOTH its banned list and its live ignoreip exemptions.
func TestFail2BanBansHandler_MultipleJailsSomeBannedSomeNot(t *testing.T) {
	runner := newFakeFail2BanRunner()
	runner.on(fakeFail2BanResponse{output: "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, sshpiperd\n"}, "status")
	runner.on(fakeFail2BanResponse{output: "Status for the jail: sshd\n`- Actions\n   `- Banned IP list:\t203.0.113.7\n"}, "status", "sshd")
	runner.on(fakeFail2BanResponse{output: "These IP addresses/networks are ignored:\n|- 127.0.0.0/8\n`- 10.0.0.0/8\n"}, "get", "sshd", "ignoreip")
	runner.on(fakeFail2BanResponse{output: "Status for the jail: sshpiperd\n`- Actions\n   `- Banned IP list:\t\n"}, "status", "sshpiperd")
	runner.on(fakeFail2BanResponse{output: "No IP address/network is ignored\n"}, "get", "sshpiperd", "ignoreip")

	m := newManagerForFail2BanTest(t, runner)
	handler := auth.SentinelHMACMiddleware(m.adminSecret, m.Fail2BanBansHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, signedGet("/sentinel/fail2ban/bans", fail2banAdminSecret))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got Fail2BanBansResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	want := Fail2BanBansResponse{Jails: []Fail2BanJailBans{
		{Jail: "sshd", Banned: []string{"203.0.113.7"}, IgnoreIP: []string{"127.0.0.0/8", "10.0.0.0/8"}},
		{Jail: "sshpiperd", Banned: []string{}, IgnoreIP: []string{}},
	}}
	if len(got.Jails) != len(want.Jails) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want.Jails {
		g, w := got.Jails[i], want.Jails[i]
		if g.Jail != w.Jail || !stringSlicesEqual(g.Banned, w.Banned) || !stringSlicesEqual(g.IgnoreIP, w.IgnoreIP) {
			t.Fatalf("jail %d: got %+v, want %+v", i, g, w)
		}
	}
}

// TestFail2BanBansHandler_404WhenFail2BanNotInstalled is acceptance
// criterion 4: fail2ban not being available must surface as 404, not
// 500, so a caller can tell "this sentinel cannot do that" apart from
// an actual server bug.
func TestFail2BanBansHandler_404WhenFail2BanNotInstalled(t *testing.T) {
	runner := newFakeFail2BanRunner()
	runner.on(fakeFail2BanResponse{err: fmt.Errorf(`exec: "fail2ban-client": executable file not found in $PATH`)}, "status")

	m := newManagerForFail2BanTest(t, runner)
	handler := auth.SentinelHMACMiddleware(m.adminSecret, m.Fail2BanBansHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, signedGet("/sentinel/fail2ban/bans", fail2banAdminSecret))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d, body = %s", rec.Code, rec.Body.String())
	}
}

// TestFail2BanBansHandler_RejectsUnsignedRequest mirrors the existing
// tunnel-tokens / byoc-routes admin-gating tests: an unauthenticated
// (or wrong-secret) request must never reach fail2ban-client at all.
func TestFail2BanBansHandler_RejectsUnsignedRequest(t *testing.T) {
	runner := newFakeFail2BanRunner() // no responses scripted — any call fails the test
	m := newManagerForFail2BanTest(t, runner)
	handler := auth.SentinelHMACMiddleware(m.adminSecret, m.Fail2BanBansHandler())

	req := httptest.NewRequest(http.MethodGet, "/sentinel/fail2ban/bans", nil) // no SignSentinelRequest
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned request must be rejected; got %d", rec.Code)
	}
	if runner.callCount() != 0 {
		t.Fatalf("handler must not run fail2ban-client for a rejected request; got %d calls", runner.callCount())
	}
}

// TestFail2BanBansHandler_WrongSecretRejected proves the admin secret
// gate is what's enforcing this, not just "any signature" — signing
// with the cluster-wide HMAC secret instead of the admin secret must
// still be rejected (mirrors
// TestTunnelTokenRegisterHandler_AdminSecretIndependentOfHMACSecret).
func TestFail2BanBansHandler_WrongSecretRejected(t *testing.T) {
	const wrongSecret = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	runner := newFakeFail2BanRunner()
	m := newManagerForFail2BanTest(t, runner)
	handler := auth.SentinelHMACMiddleware(m.adminSecret, m.Fail2BanBansHandler())

	req := httptest.NewRequest(http.MethodGet, "/sentinel/fail2ban/bans", nil)
	auth.SignSentinelRequest(req, []byte(wrongSecret))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-secret request must be rejected; got %d", rec.Code)
	}
}

// ---- POST /sentinel/fail2ban/unban ---------------------------------

// TestFail2BanUnbanHandler_SpecificJailHappyPath is acceptance
// criterion 2 (specific jail case): unbanning an IP that IS banned on
// the named jail reports success and names that jail.
func TestFail2BanUnbanHandler_SpecificJailHappyPath(t *testing.T) {
	runner := newFakeFail2BanRunner()
	runner.on(fakeFail2BanResponse{output: "1\n"}, "set", "sshpiperd", "unbanip", "203.0.113.7")

	m := newManagerForFail2BanTest(t, runner)
	handler := auth.SentinelHMACMiddleware(m.adminSecret, m.Fail2BanUnbanHandler())
	req := signedPost(t, "/sentinel/fail2ban/unban", fail2banAdminSecret, Fail2BanUnbanRequest{Jail: "sshpiperd", IP: "203.0.113.7"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got Fail2BanUnbanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	if !got.Unbanned || !stringSlicesEqual(got.Jails, []string{"sshpiperd"}) {
		t.Fatalf("got %+v, want unbanned=true jails=[sshpiperd]", got)
	}
}

// TestFail2BanUnbanHandler_EmptyJailHitsEveryConfiguredJail is
// acceptance criterion 2 (empty-jail case): an empty jail means "try
// every jail this sentinel has configured" — the ban normally lives on
// only one host in a multi-sentinel deployment, so only the jails
// where the IP actually WAS banned should come back in the response.
func TestFail2BanUnbanHandler_EmptyJailHitsEveryConfiguredJail(t *testing.T) {
	runner := newFakeFail2BanRunner()
	runner.on(fakeFail2BanResponse{output: "Status\n`- Jail list:\tsshd, sshpiperd\n"}, "status")
	runner.on(fakeFail2BanResponse{output: "0\n"}, "set", "sshd", "unbanip", "203.0.113.7")
	runner.on(fakeFail2BanResponse{output: "1\n"}, "set", "sshpiperd", "unbanip", "203.0.113.7")

	m := newManagerForFail2BanTest(t, runner)
	handler := auth.SentinelHMACMiddleware(m.adminSecret, m.Fail2BanUnbanHandler())
	req := signedPost(t, "/sentinel/fail2ban/unban", fail2banAdminSecret, Fail2BanUnbanRequest{IP: "203.0.113.7"}) // no Jail
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got Fail2BanUnbanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	if !got.Unbanned || !stringSlicesEqual(got.Jails, []string{"sshpiperd"}) {
		t.Fatalf("got %+v, want unbanned=true jails=[sshpiperd] (sshd never had the ban)", got)
	}
}

// TestFail2BanUnbanHandler_NotBannedIsSuccessNotError is acceptance
// criterion 2's specific carve-out: unbanning an address that isn't
// banned must be a 200 with unbanned=false, never an error status —
// exactly the routine outcome a multi-sentinel deployment sees when it
// asks every host to clear an address that was only ever banned on one
// of them.
func TestFail2BanUnbanHandler_NotBannedIsSuccessNotError(t *testing.T) {
	runner := newFakeFail2BanRunner()
	runner.on(fakeFail2BanResponse{output: "0\n"}, "set", "sshpiperd", "unbanip", "198.51.100.1")

	m := newManagerForFail2BanTest(t, runner)
	handler := auth.SentinelHMACMiddleware(m.adminSecret, m.Fail2BanUnbanHandler())
	req := signedPost(t, "/sentinel/fail2ban/unban", fail2banAdminSecret, Fail2BanUnbanRequest{Jail: "sshpiperd", IP: "198.51.100.1"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("not-banned unban must be 200, got %d, body = %s", rec.Code, rec.Body.String())
	}
	var got Fail2BanUnbanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	if got.Unbanned {
		t.Fatalf("got unbanned=true, want false: %+v", got)
	}
	if len(got.Jails) != 0 {
		t.Fatalf("got jails=%v, want empty", got.Jails)
	}
}

// TestFail2BanUnbanHandler_RejectsCIDRBeforeAnyCommand is acceptance
// criterion 3: a CIDR in `ip` must be rejected with 400 BEFORE it ever
// reaches fail2ban-client — silently unbanning only the network address
// of a prefix would look like it worked but wouldn't. Asserting zero
// calls on the fake runner is the point: this proves the rejection
// happens ahead of any exec, not just that the final status differs.
func TestFail2BanUnbanHandler_RejectsCIDRBeforeAnyCommand(t *testing.T) {
	runner := newFakeFail2BanRunner() // no responses scripted
	m := newManagerForFail2BanTest(t, runner)
	handler := auth.SentinelHMACMiddleware(m.adminSecret, m.Fail2BanUnbanHandler())
	req := signedPost(t, "/sentinel/fail2ban/unban", fail2banAdminSecret, Fail2BanUnbanRequest{Jail: "sshpiperd", IP: "203.0.113.0/24"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for CIDR input, got %d, body = %s", rec.Code, rec.Body.String())
	}
	if runner.callCount() != 0 {
		t.Fatalf("CIDR must be rejected before any fail2ban-client call; got %d calls", runner.callCount())
	}
}

// TestFail2BanUnbanHandler_RejectsEmptyIP guards the same validation
// path for an omitted ip — net.ParseIP("") is also invalid, and an
// empty IP must not be treated as "unban nothing, succeed anyway".
func TestFail2BanUnbanHandler_RejectsEmptyIP(t *testing.T) {
	runner := newFakeFail2BanRunner()
	m := newManagerForFail2BanTest(t, runner)
	handler := auth.SentinelHMACMiddleware(m.adminSecret, m.Fail2BanUnbanHandler())
	req := signedPost(t, "/sentinel/fail2ban/unban", fail2banAdminSecret, Fail2BanUnbanRequest{Jail: "sshpiperd"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for empty ip, got %d, body = %s", rec.Code, rec.Body.String())
	}
	if runner.callCount() != 0 {
		t.Fatalf("empty ip must be rejected before any fail2ban-client call; got %d calls", runner.callCount())
	}
}

// TestFail2BanUnbanHandler_NonexistentJailReturns404 is acceptance
// criterion 4 (unban side): a named jail fail2ban-client doesn't
// recognize must be a 404, matching fail2ban-client's own "... does
// not exist" rejection (confirmed against a real fail2ban-client
// install during development of this PR).
func TestFail2BanUnbanHandler_NonexistentJailReturns404(t *testing.T) {
	runner := newFakeFail2BanRunner()
	runner.on(fakeFail2BanResponse{
		output: "2026-09-23 00:00:00,000 fail2ban [1]: ERROR   NOK: ('bogusjail',)\nSorry but the jail 'bogusjail' does not exist\n",
		err:    fmt.Errorf("exit status 255"),
	}, "set", "bogusjail", "unbanip", "203.0.113.7")

	m := newManagerForFail2BanTest(t, runner)
	handler := auth.SentinelHMACMiddleware(m.adminSecret, m.Fail2BanUnbanHandler())
	req := signedPost(t, "/sentinel/fail2ban/unban", fail2banAdminSecret, Fail2BanUnbanRequest{Jail: "bogusjail", IP: "203.0.113.7"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for a nonexistent jail, got %d, body = %s", rec.Code, rec.Body.String())
	}
}

// TestFail2BanUnbanHandler_RejectsUnsignedRequest mirrors the tunnel-
// tokens admin-gating test for the unban side.
func TestFail2BanUnbanHandler_RejectsUnsignedRequest(t *testing.T) {
	runner := newFakeFail2BanRunner()
	m := newManagerForFail2BanTest(t, runner)
	handler := auth.SentinelHMACMiddleware(m.adminSecret, m.Fail2BanUnbanHandler())

	body, _ := json.Marshal(Fail2BanUnbanRequest{Jail: "sshpiperd", IP: "203.0.113.7"})
	req := httptest.NewRequest(http.MethodPost, "/sentinel/fail2ban/unban", bytes.NewReader(body)) // no SignSentinelRequest
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned request must be rejected; got %d", rec.Code)
	}
	if runner.callCount() != 0 {
		t.Fatalf("handler must not run fail2ban-client for a rejected request; got %d calls", runner.callCount())
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
