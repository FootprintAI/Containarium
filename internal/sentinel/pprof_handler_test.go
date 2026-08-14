package sentinel

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
)

// #1352: the sentinel had no way to produce a heap profile, so the leak in
// #1349 was OOM-killed at 565 MB having never been profiled and could not be
// root-caused without shipping an instrumented build to production.
//
// These tests pin the two halves that matter: the profile is actually usable
// by `go tool pprof` (not just "some bytes came back"), and it is gated behind
// the ADMIN secret — a heap dump contains whatever the process holds in
// memory, which on a sentinel includes tunnel-join tokens and TLS key
// material, so it is strictly more sensitive than the cluster-wide daemon
// secret's blast radius.

const (
	testPprofAdminSecret = "pprof-admin-secret-at-least-32-bytes!!"
	testPprofHMACSecret  = "pprof-daemon-hmac-secret-32-bytes-long!"
)

// newPprofTestServer serves the REAL binary-server route table, for the same
// reason newPeerProxyTestServer does (#1102): which middleware a route is
// registered behind IS the fix here, so a hand-wired mux would keep these
// tests green through a revert of the gate.
func newPprofTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	m := &Manager{
		backends:    NewBackendPool(),
		adminSecret: []byte(testPprofAdminSecret),
		hmacSecret:  []byte(testPprofHMACSecret),
	}
	srv := httptest.NewServer(buildBinaryServerMux("/nonexistent/containarium", m))
	t.Cleanup(srv.Close)
	return srv
}

// getPprof issues a GET, signing with secret when it is non-empty.
func getPprof(t *testing.T, srv *httptest.Server, path, secret string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if secret != "" {
		auth.SignSentinelRequest(req, []byte(secret))
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, body
}

func TestPprofRequiresAdminSecret(t *testing.T) {
	srv := newPprofTestServer(t)

	// Unsigned — the state the pentest module (module_web.go) probes for.
	if code, _ := getPprof(t, srv, "/debug/pprof/heap", ""); code != http.StatusUnauthorized {
		t.Fatalf("unsigned /debug/pprof/heap = %d, want 401 — profile endpoint is exposed", code)
	}

	// Signed with the cluster-wide DAEMON secret. Every backend daemon holds
	// this one for keysync/certsync; a heap dump is a bigger capability than
	// that, so it must not be sufficient here.
	if code, _ := getPprof(t, srv, "/debug/pprof/heap", testPprofHMACSecret); code != http.StatusUnauthorized {
		t.Fatalf("/debug/pprof/heap signed with the daemon HMAC secret = %d, want 401 — "+
			"gated on the wrong secret, every daemon in the cluster can dump sentinel memory", code)
	}

	// Signed with the admin secret — the one legitimate caller.
	if code, _ := getPprof(t, srv, "/debug/pprof/heap", testPprofAdminSecret); code != http.StatusOK {
		t.Fatalf("/debug/pprof/heap signed with the admin secret = %d, want 200", code)
	}
}

// TestPprofHeapIsReadableByGoToolPprof is the acceptance criterion for #1352:
// not "bytes came back" but "the bytes are a profile go tool pprof can open,
// with the sample type you need to find a leak".
func TestPprofHeapIsReadableByGoToolPprof(t *testing.T) {
	srv := newPprofTestServer(t)

	code, body := getPprof(t, srv, "/debug/pprof/heap", testPprofAdminSecret)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}

	// A pprof profile on the wire is gzipped protobuf; go tool pprof rejects
	// anything else. Decompressing here proves the framing without taking a
	// dependency on github.com/google/pprof (which drags a readline terminal
	// library into the module graph for a parse we can do structurally).
	raw := gunzipOrFail(t, body)

	// Sample-type names live in the profile's string table as plain UTF-8, so
	// they are assertable on the decompressed bytes. inuse_space is what
	// answers "what is holding 480 MB right now" — the actual question in
	// #1349, and the one sample type this endpoint exists to deliver.
	for _, want := range []string{"inuse_space", "inuse_objects", "space", "bytes"} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("heap profile string table has no %q — not a usable heap profile", want)
		}
	}
	if len(raw) < 128 {
		t.Fatalf("heap profile is %d bytes decompressed — too small to contain samples", len(raw))
	}
}

// gunzipOrFail decompresses a pprof response body, failing the test with the
// leading bytes when it is not a valid gzip stream.
func gunzipOrFail(t *testing.T, body []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("response is not gzipped protobuf, so go tool pprof cannot read it: %v (first 32 bytes: %q)",
			err, truncBytes(body, 32))
	}
	defer func() { _ = zr.Close() }()
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("truncated/corrupt gzip stream: %v", err)
	}
	return raw
}

func TestPprofGoroutineProfileAndDebugTextMode(t *testing.T) {
	srv := newPprofTestServer(t)

	// debug=0 (default) → parseable binary profile.
	code, body := getPprof(t, srv, "/debug/pprof/goroutine", testPprofAdminSecret)
	if code != http.StatusOK {
		t.Fatalf("goroutine status = %d, want 200", code)
	}
	if raw := gunzipOrFail(t, body); !bytes.Contains(raw, []byte("goroutine")) {
		t.Error("goroutine profile string table does not mention goroutines")
	}

	// debug=1 → human-readable text, for reading over SSH without go tool pprof.
	code, body = getPprof(t, srv, "/debug/pprof/goroutine?debug=1", testPprofAdminSecret)
	if code != http.StatusOK {
		t.Fatalf("goroutine?debug=1 status = %d, want 200", code)
	}
	if !bytes.Contains(body, []byte("goroutine profile")) {
		t.Fatalf("debug=1 output is not the text format; got first 120 bytes: %q", truncBytes(body, 120))
	}
}

func TestPprofIndexListsProfiles(t *testing.T) {
	srv := newPprofTestServer(t)

	code, body := getPprof(t, srv, "/debug/pprof/", testPprofAdminSecret)
	if code != http.StatusOK {
		t.Fatalf("index status = %d, want 200", code)
	}
	for _, want := range []string{"heap", "goroutine", "allocs"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("index does not mention %q; got: %s", want, truncBytes(body, 300))
		}
	}
}

func TestPprofUnknownProfileIs404(t *testing.T) {
	srv := newPprofTestServer(t)

	code, body := getPprof(t, srv, "/debug/pprof/not-a-real-profile", testPprofAdminSecret)
	if code != http.StatusNotFound {
		t.Fatalf("unknown profile = %d, want 404 (body: %s)", code, truncBytes(body, 200))
	}
}

func TestPprofCPUSecondsIsValidatedAndBounded(t *testing.T) {
	srv := newPprofTestServer(t)

	for _, tc := range []struct {
		name  string
		query string
	}{
		{"non-numeric", "?seconds=forever"},
		{"zero", "?seconds=0"},
		{"negative", "?seconds=-5"},
		{"over the cap", "?seconds=600"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := getPprof(t, srv, "/debug/pprof/profile"+tc.query, testPprofAdminSecret)
			if code != http.StatusBadRequest {
				t.Fatalf("seconds%s = %d, want 400", tc.query, code)
			}
		})
	}
}

// TestPprofNotRegisteredOnDefaultServeMux guards the trap in this change.
//
// Importing net/http/pprof — blank OR named — runs its init(), which registers
// /debug/pprof/* on http.DefaultServeMux as a side effect. Nothing serves
// DefaultServeMux today, so that would be invisible; the day someone adds an
// http.ListenAndServe(addr, nil) anywhere in this binary (the daemon, the
// agent-box and the sentinel are all the same binary) it silently becomes an
// UNAUTHENTICATED heap-dump endpoint on that port. This handler uses
// runtime/pprof directly to avoid that, and this test fails if a future change
// reintroduces the import.
func TestPprofNotRegisteredOnDefaultServeMux(t *testing.T) {
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/heap", "/debug/pprof/profile"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if _, pattern := http.DefaultServeMux.Handler(req); pattern != "" {
			t.Fatalf("%s is registered on http.DefaultServeMux (pattern %q) — "+
				"something imported net/http/pprof. Its init() exposes an "+
				"unauthenticated profile endpoint on any server that uses the "+
				"default mux; use runtime/pprof directly instead.", path, pattern)
		}
	}
}

func truncBytes(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
