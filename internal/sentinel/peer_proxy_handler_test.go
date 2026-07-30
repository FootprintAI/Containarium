package sentinel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
)

// #1102: /peer/ was the one route on the binary-server mux with no
// authentication, while every neighbouring /sentinel/* route is HMAC
// gated. These tests pin both halves of the fix — the gate itself, and
// the uniform rejection that stops an authorized caller from using the
// route to enumerate which backends a sentinel fronts.

const testAdminSecret = "peer-proxy-admin-secret-32-bytes-long!"

// newPeerProxyTestServer serves the REAL binary-server route table over
// a manager holding one backend that points at a stub daemon.
//
// It deliberately calls buildBinaryServerMux rather than registering
// /peer/ itself. An earlier version of this file built its own mux, and
// mutation testing showed the consequence: removing the HMAC middleware
// from binaryserver.go entirely — i.e. reverting the whole fix — left
// every test in this file green, because they were exercising a route
// table the test had wired correctly by hand. Which middleware a route
// is registered behind IS the fix for #1102, so it has to be the real
// registration under test.
func newPeerProxyTestServer(t *testing.T, adminSecret string) (*httptest.Server, string) {
	t.Helper()

	// Stub daemon standing in for the backend's health-port listener.
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "daemon saw "+r.URL.Path)
	}))
	t.Cleanup(daemon.Close)

	du, err := url.Parse(daemon.URL)
	if err != nil {
		t.Fatalf("parse daemon url: %v", err)
	}
	port, err := strconv.Atoi(du.Port())
	if err != nil {
		t.Fatalf("daemon port: %v", err)
	}

	m := &Manager{
		backends:    NewBackendPool(),
		adminSecret: []byte(adminSecret),
	}
	m.config.HealthPort = port
	m.backends.Add(&Backend{ID: "tunnel-known-1", Type: BackendTunnel, IP: du.Hostname()})

	// binaryPath only feeds the /containarium download routes, which these
	// tests never call; a path that doesn't exist is fine here (StartBinaryServer
	// is what stats it, and we deliberately don't go through that — it binds a
	// real port and requires the installed binary).
	srv := httptest.NewServer(buildBinaryServerMux("/nonexistent/containarium", m))
	t.Cleanup(srv.Close)
	return srv, daemon.URL
}

// doPeer issues a request to path, signing it with secret when signed.
func doPeer(t *testing.T, srv *httptest.Server, path, secret string, signed bool) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if signed {
		auth.SignSentinelRequest(req, []byte(secret))
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// TestPeerProxy_UnsignedRequestRejected is the core of #1102: this route
// used to serve anyone who could reach the port.
func TestPeerProxy_UnsignedRequestRejected(t *testing.T) {
	srv, _ := newPeerProxyTestServer(t, testAdminSecret)

	code, _ := doPeer(t, srv, "/peer/tunnel-known-1/v1/containers", "", false)
	if code != http.StatusUnauthorized {
		t.Errorf("unsigned /peer/ = %d, want 401 — the route must not be reachable unauthenticated", code)
	}
}

// TestPeerProxy_WrongSecretRejected: holding *a* sentinel secret is not
// enough. The daemon-wide HMAC secret is distributed to every backend
// host; the admin secret is the control plane's. Gating on the wrong one
// would leave the route reachable from any host in the fleet, which is
// exactly the population #1102 is worried about.
func TestPeerProxy_WrongSecretRejected(t *testing.T) {
	srv, _ := newPeerProxyTestServer(t, testAdminSecret)

	code, _ := doPeer(t, srv, "/peer/tunnel-known-1/v1/containers", "a-different-secret-of-sufficient-length", true)
	if code != http.StatusUnauthorized {
		t.Errorf("wrongly-signed /peer/ = %d, want 401", code)
	}
}

// TestPeerProxy_SignedRequestProxies is the control. Without it every
// assertion here would pass on a route that rejects everything.
func TestPeerProxy_SignedRequestProxies(t *testing.T) {
	srv, _ := newPeerProxyTestServer(t, testAdminSecret)

	code, body := doPeer(t, srv, "/peer/tunnel-known-1/v1/containers", testAdminSecret, true)
	if code != http.StatusOK {
		t.Fatalf("signed /peer/ = %d, want 200: %s", code, body)
	}
	// The daemon must receive the path with the /peer/<id> prefix
	// stripped — the proxy rewrite still has to work behind the gate.
	if want := "daemon saw /v1/containers"; body != want {
		t.Errorf("daemon got %q, want %q", body, want)
	}
}

// TestPeerProxy_UnknownBackendIsNotDistinguishable is the enumeration
// half. A caller past the gate must not be able to map which backends
// this sentinel fronts by diffing rejections — the id namespace is flat
// and global across every org on the sentinel.
func TestPeerProxy_UnknownBackendIsNotDistinguishable(t *testing.T) {
	srv, _ := newPeerProxyTestServer(t, testAdminSecret)

	unknownCode, unknownBody := doPeer(t, srv, "/peer/tunnel-someone-elses/v1/containers", testAdminSecret, true)
	malformedCode, malformedBody := doPeer(t, srv, "/peer/tunnel-someone-elses", testAdminSecret, true)

	if unknownCode != http.StatusNotFound {
		t.Errorf("unknown backend = %d, want 404", unknownCode)
	}
	if malformedCode != unknownCode {
		t.Errorf("malformed path = %d but unknown backend = %d; rejections must be indistinguishable",
			malformedCode, unknownCode)
	}
	if malformedBody != unknownBody {
		t.Errorf("rejection bodies differ:\n malformed: %q\n unknown:   %q", malformedBody, unknownBody)
	}
}

// TestPeerProxy_RejectionDoesNotEchoBackendID: the old handler replied
// `backend "tunnel-x" not found`, reflecting caller-controlled input
// straight back. Beyond confirming the id parsed, a reflected value in
// an error body is the ingredient for response-splitting and for
// log-poisoning downstream.
func TestPeerProxy_RejectionDoesNotEchoBackendID(t *testing.T) {
	srv, _ := newPeerProxyTestServer(t, testAdminSecret)

	const probe = "tunnel-victim-org-gpu-box"
	_, body := doPeer(t, srv, "/peer/"+probe+"/v1/containers", testAdminSecret, true)
	if strings.Contains(body, probe) {
		t.Errorf("rejection echoed the requested backend id back: %q", body)
	}
}

// TestPeerProxy_EmptyBackendIDRejected: `/peer//v1/x` parses to an empty
// id, which BackendPool.Get would look up as "" — a miss today, but the
// handler must not depend on that staying true. Rejected at parse time.
//
// Driven against the handler directly rather than through the test
// server: both net/http's client and ServeMux collapse the `//` before
// the handler ever sees it, so an end-to-end request cannot express this
// input at all (it arrives as `/peer/v1/containers`, a different case).
// Going through the stack here would test URL normalization and report
// it as coverage of this guard.
func TestPeerProxy_EmptyBackendIDRejected(t *testing.T) {
	m := &Manager{backends: NewBackendPool(), adminSecret: []byte(testAdminSecret)}

	req := httptest.NewRequest(http.MethodGet, "http://sentinel/x", nil)
	req.URL.Path = "/peer//v1/containers" // set post-parse so it survives verbatim
	rec := httptest.NewRecorder()

	m.PeerProxyHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("empty backend id = %d, want 404", rec.Code)
	}
}

// TestPeerProxy_UnconfiguredAdminSecretFailsClosed pins the deployment
// contract, and it is the one behaviour change an operator can be bitten
// by: a sentinel with no CONTAINARIUM_SENTINEL_ADMIN_SECRET now refuses
// the peer proxy outright rather than serving it to anyone.
//
// Fail-closed is the deliberate choice — a fail-open fallback would mean
// the fix is absent exactly on the hosts whose operator never configured
// the secret, which is the population most likely to need it. NewManager
// logs this at startup so it is diagnosable.
func TestPeerProxy_UnconfiguredAdminSecretFailsClosed(t *testing.T) {
	srv, _ := newPeerProxyTestServer(t, "")

	code, _ := doPeer(t, srv, "/peer/tunnel-known-1/v1/containers", "", false)
	if code != http.StatusUnauthorized {
		t.Errorf("unconfigured admin secret = %d, want 401 (fail closed)", code)
	}
}

func TestSplitPeerPath(t *testing.T) {
	tests := []struct {
		name, path      string
		wantID, wantRem string
		wantOK          bool
	}{
		{"normal", "/peer/tunnel-a/v1/containers", "tunnel-a", "/v1/containers", true},
		{"root path", "/peer/tunnel-a/", "tunnel-a", "/", true},
		{"nested", "/peer/tunnel-a/v1/containers/abc/ssh-keys", "tunnel-a", "/v1/containers/abc/ssh-keys", true},
		{"no trailing segment", "/peer/tunnel-a", "", "", false},
		{"empty id", "/peer//v1/containers", "", "", false},
		{"bare prefix", "/peer/", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, rem, ok := splitPeerPath(tc.path)
			if ok != tc.wantOK || id != tc.wantID || rem != tc.wantRem {
				t.Errorf("splitPeerPath(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.path, id, rem, ok, tc.wantID, tc.wantRem, tc.wantOK)
			}
		})
	}
}
