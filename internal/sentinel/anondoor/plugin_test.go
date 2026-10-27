package anondoor

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

// fakeConn is the libplugin.ConnMetadata a test hands the plugin.
type fakeConn struct {
	user, remote, id string
	meta             map[string]string
}

func (c fakeConn) User() string            { return c.user }
func (c fakeConn) RemoteAddr() string      { return c.remote }
func (c fakeConn) UniqueID() string        { return c.id }
func (c fakeConn) GetMeta(k string) string { return c.meta[k] }

func testKey(t *testing.T) (wire []byte, fingerprint, authorizedLine string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub.Marshal(), ssh.FingerprintSHA256(sshPub), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func writeUpstreamKey(t *testing.T) (path string, content []byte) {
	t.Helper()
	content = []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n")
	path = filepath.Join(t.TempDir(), "upstream_key")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, content
}

type daemonCall struct {
	path, method string
	signed       bool
	body         map[string]any
}

// fakeDaemon answers /v1/anon/boxes:ensure with a canned status + body and
// records what it was asked.
func fakeDaemon(t *testing.T, status int, body string, delay time.Duration) (*httptest.Server, *daemonCall) {
	t.Helper()
	call := &daemonCall{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call.path, call.method = r.URL.Path, r.Method
		call.signed = r.Header.Get("X-Test-Signed") == "1"
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &call.body)
		if delay > 0 {
			time.Sleep(delay)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, call
}

func newPlugin(t *testing.T, daemonURL, keyPath string, mut func(*Config)) *Plugin {
	t.Helper()
	cfg := Config{
		DaemonURL:       daemonURL,
		UpstreamKeyPath: keyPath,
		Sign:            func(r *http.Request) { r.Header.Set("X-Test-Signed", "1") },
		Timeout:         2 * time.Second,
		Logf:            t.Logf,
	}
	if mut != nil {
		mut(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const okBody = `{"boxName":"anon-1a2b3c4d-container","sshHost":"10.100.0.57","sshPort":22,"sshUser":"anon-1a2b3c4d","ttlExpiresAt":"2026-10-01T16:00:00Z","reused":false,"previousExpired":false}`

func TestPublicKey_OKBecomesUpstreamPipe(t *testing.T) {
	srv, call := fakeDaemon(t, http.StatusOK, okBody, 0)
	keyPath, keyBytes := writeUpstreamKey(t)
	p := newPlugin(t, srv.URL, keyPath, nil)
	wire, fp, line := testKey(t)

	up, err := p.PluginConfig().PublicKeyCallback(fakeConn{user: "whatever", remote: "198.51.100.7:51234", id: "c1"}, wire)
	if err != nil {
		t.Fatalf("PublicKeyCallback: %v", err)
	}

	// What the daemon was asked.
	if call.method != http.MethodPost || call.path != "/v1/anon/boxes:ensure" {
		t.Errorf("daemon got %s %s", call.method, call.path)
	}
	if !call.signed {
		t.Errorf("request was not passed through the Sign hook")
	}
	if call.body["publicKey"] != line || call.body["fingerprint"] != fp || call.body["sourceIp"] != "198.51.100.7" {
		t.Errorf("body = %v", call.body)
	}

	// What sshpiper gets back.
	if up.GetOrGenerateUri() != "tcp://10.100.0.57:22" || up.UserName != "anon-1a2b3c4d" || !up.IgnoreHostKey { //nolint:staticcheck // asserting the deprecated flag tenant pipes rely on
		t.Errorf("upstream = uri %s user %s ignoreHostKey %v", up.GetOrGenerateUri(), up.UserName, up.IgnoreHostKey) //nolint:staticcheck // same
	}
	pk, ok := up.Auth.(*libplugin.Upstream_PrivateKey)
	if !ok || string(pk.PrivateKey.PrivateKey) != string(keyBytes) {
		t.Errorf("upstream auth = %T, want the upstream private key file verbatim", up.Auth)
	}
}

func TestPublicKey_DaemonRejectsAuth(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string // substring of the returned error
	}{
		{"door closed (gateway error shape)", http.StatusPreconditionFailed, `{"error":"anonymous door is closed for maintenance","code":412}`, "closed for maintenance"},
		{"full (grpc-gateway message shape)", http.StatusTooManyRequests, `{"code":8,"message":"we're full, sign up for a guaranteed box"}`, "we're full"},
		{"forbidden, no body", http.StatusForbidden, ``, "403"},
		{"garbage 200", http.StatusOK, `not json`, "decode"},
		{"200 without an endpoint", http.StatusOK, `{"boxName":"x"}`, "no ssh endpoint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _ := fakeDaemon(t, tt.status, tt.body, 0)
			keyPath, _ := writeUpstreamKey(t)
			p := newPlugin(t, srv.URL, keyPath, nil)
			wire, _, _ := testKey(t)

			up, err := p.PluginConfig().PublicKeyCallback(fakeConn{remote: "198.51.100.7:1"}, wire)
			if err == nil || up != nil {
				t.Fatalf("want rejection, got up=%v err=%v", up, err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestPublicKey_DaemonTimeoutRejectsWithinDeadline(t *testing.T) {
	srv, _ := fakeDaemon(t, http.StatusOK, okBody, 2*time.Second)
	keyPath, _ := writeUpstreamKey(t)
	p := newPlugin(t, srv.URL, keyPath, func(c *Config) { c.Timeout = 100 * time.Millisecond })
	wire, _, _ := testKey(t)

	start := time.Now()
	_, err := p.PluginConfig().PublicKeyCallback(fakeConn{remote: "198.51.100.7:1"}, wire)
	if err == nil {
		t.Fatal("want timeout error")
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("took %v, want the plugin's own deadline (~100ms) to cut it off", took)
	}
	if !strings.Contains(err.Error(), "try again") {
		t.Errorf("err = %q, want a 'try again' message", err)
	}
}

func TestPublicKey_DaemonUnreachable(t *testing.T) {
	keyPath, _ := writeUpstreamKey(t)
	p := newPlugin(t, "http://127.0.0.1:1", keyPath, func(c *Config) { c.Timeout = time.Second })
	wire, _, _ := testKey(t)
	if _, err := p.PluginConfig().PublicKeyCallback(fakeConn{remote: "198.51.100.7:1"}, wire); err == nil || !strings.Contains(err.Error(), "try again") {
		t.Errorf("err = %v, want 'try again'", err)
	}
}

func TestPublicKey_BadKeyBytesRejected(t *testing.T) {
	srv, call := fakeDaemon(t, http.StatusOK, okBody, 0)
	keyPath, _ := writeUpstreamKey(t)
	p := newPlugin(t, srv.URL, keyPath, nil)

	if _, err := p.PluginConfig().PublicKeyCallback(fakeConn{remote: "198.51.100.7:1"}, []byte("not a wire key")); err == nil {
		t.Fatal("want error")
	}
	if call.path != "" {
		t.Errorf("daemon must not be called for an unparseable key")
	}
}

func TestPublicKey_MissingUpstreamKeyRejectsAfterEnsure(t *testing.T) {
	// The box exists but the sentinel cannot authenticate to it: reject
	// loudly rather than hand sshpiper a pipe with no credential.
	srv, _ := fakeDaemon(t, http.StatusOK, okBody, 0)
	p := newPlugin(t, srv.URL, filepath.Join(t.TempDir(), "missing"), nil)
	wire, _, _ := testKey(t)
	if _, err := p.PluginConfig().PublicKeyCallback(fakeConn{remote: "198.51.100.7:1"}, wire); err == nil || !strings.Contains(err.Error(), "upstream key") {
		t.Errorf("err = %v, want an upstream-key error", err)
	}
}

func TestNonKeyAuthIsRefused(t *testing.T) {
	srv, call := fakeDaemon(t, http.StatusOK, okBody, 0)
	keyPath, _ := writeUpstreamKey(t)
	cfg := newPlugin(t, srv.URL, keyPath, nil).PluginConfig()

	methods, err := cfg.NextAuthMethodsCallback(fakeConn{})
	if err != nil || len(methods) != 1 || methods[0] != "publickey" {
		t.Errorf("NextAuthMethods = %v (%v), want [publickey]", methods, err)
	}
	if up, err := cfg.PasswordCallback(fakeConn{}, []byte("hunter2")); err == nil || up != nil || !strings.Contains(err.Error(), "SSH key") {
		t.Errorf("password: up=%v err=%v, want 'use an SSH key'", up, err)
	}
	if up, err := cfg.KeyboardInteractiveCallback(fakeConn{}, nil); err == nil || up != nil || !strings.Contains(err.Error(), "SSH key") {
		t.Errorf("keyboard-interactive: up=%v err=%v, want 'use an SSH key'", up, err)
	}
	if up, err := cfg.NoClientAuthCallback(fakeConn{}); err == nil || up != nil {
		t.Errorf("none auth: up=%v err=%v, want refusal", up, err)
	}
	if call.path != "" {
		t.Errorf("daemon must never be called for non-key auth")
	}
}

func TestBanner(t *testing.T) {
	keyPath, _ := writeUpstreamKey(t)
	p := newPlugin(t, "http://127.0.0.1:1", keyPath, func(c *Config) { c.Banner = "hello door" })
	if got := p.PluginConfig().BannerCallback(fakeConn{}); got != "hello door" {
		t.Errorf("banner = %q", got)
	}
	q := newPlugin(t, "http://127.0.0.1:1", keyPath, nil)
	if got := q.PluginConfig().BannerCallback(fakeConn{}); !strings.Contains(got, "SSH key") {
		t.Errorf("default banner should tell the user to use an SSH key: %q", got)
	}
}

func TestNew_Validation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("empty DaemonURL must be rejected")
	}
	if _, err := New(Config{DaemonURL: "::not a url"}); err == nil {
		t.Error("bad DaemonURL must be rejected")
	}
	p, err := New(Config{DaemonURL: "http://daemon:8080/"})
	if err != nil {
		t.Fatal(err)
	}
	if p.cfg.Timeout != DefaultTimeout || p.cfg.UpstreamKeyPath != DefaultUpstreamKeyPath {
		t.Errorf("defaults not applied: %+v", p.cfg)
	}
}
