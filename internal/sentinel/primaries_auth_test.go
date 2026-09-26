package sentinel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
)

// /sentinel/primaries (GET/POST/DELETE) was the one route on the binary-server
// mux that let a network caller read the full primary registry, overwrite any
// pool's declared routing target, or delete it outright — no credential of
// any kind. These tests pin the fix the same way #1102 pinned /peer/: they
// exercise the REAL route table via buildBinaryServerMux, not a hand-rolled
// mux, so removing the middleware in binaryserver.go would fail them.

const testPrimariesSecret = "primaries-auth-test-secret-32-bytes!"

// newPrimariesTestServer serves the real binary-server route table over a
// bare Manager — /sentinel/primaries needs no backend, no key store, just
// the primary registry and the HMAC secret under test.
func newPrimariesTestServer(t *testing.T, secret string) *httptest.Server {
	t.Helper()
	m := &Manager{
		backends:   NewBackendPool(),
		primaries:  NewPrimaryRegistry(),
		hmacSecret: []byte(secret),
	}
	srv := httptest.NewServer(buildBinaryServerMux("/nonexistent/containarium", m))
	t.Cleanup(srv.Close)
	return srv
}

func doPrimaries(t *testing.T, srv *httptest.Server, method, path, secret string, signed bool, body io.Reader) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if signed {
		auth.SignSentinelRequest(req, []byte(secret))
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBody)
}

func TestPrimariesHandler_UnsignedRequestRejected(t *testing.T) {
	srv := newPrimariesTestServer(t, testPrimariesSecret)

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/sentinel/primaries"},
		{http.MethodPost, "/sentinel/primaries"},
		{http.MethodPut, "/sentinel/primaries/some-pool"},
		{http.MethodDelete, "/sentinel/primaries/some-pool"},
	} {
		code, body := doPrimaries(t, srv, tc.method, tc.path, "", false, nil)
		if code != http.StatusUnauthorized {
			t.Errorf("%s %s: status = %d, body = %q; want 401 unsigned", tc.method, tc.path, code, body)
		}
	}
}

func TestPrimariesHandler_WrongSecretRejected(t *testing.T) {
	srv := newPrimariesTestServer(t, testPrimariesSecret)
	code, body := doPrimaries(t, srv, http.MethodGet, "/sentinel/primaries", "wrong-secret-but-still-32-bytes!!", true, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %q; want 401 wrong secret", code, body)
	}
}

func TestPrimariesHandler_SignedRequestSucceeds(t *testing.T) {
	srv := newPrimariesTestServer(t, testPrimariesSecret)

	code, body := doPrimaries(t, srv, http.MethodGet, "/sentinel/primaries", testPrimariesSecret, true, nil)
	if code != http.StatusOK {
		t.Fatalf("GET: status = %d, body = %q; want 200 signed", code, body)
	}

	reqBody := `{"pool":"p1","hostname":"h1.example.com","ip":"10.0.0.1","port":443}`
	code, body = doPrimaries(t, srv, http.MethodPost, "/sentinel/primaries", testPrimariesSecret, true, strings.NewReader(reqBody))
	if code != http.StatusCreated {
		t.Fatalf("POST: status = %d, body = %q; want 201 signed", code, body)
	}

	code, body = doPrimaries(t, srv, http.MethodDelete, "/sentinel/primaries/p1", testPrimariesSecret, true, nil)
	if code != http.StatusNoContent {
		t.Fatalf("DELETE: status = %d, body = %q; want 204 signed", code, body)
	}
}

// TestPrimariesHandler_UnconfiguredSecretFailsClosed matches
// TestPeerProxy_UnconfiguredAdminSecretFailsClosed's reasoning for the sibling
// route: a Manager started with no HMAC secret configured must refuse every
// request rather than silently passing them through unauthenticated.
func TestPrimariesHandler_UnconfiguredSecretFailsClosed(t *testing.T) {
	srv := newPrimariesTestServer(t, "")
	code, _ := doPrimaries(t, srv, http.MethodGet, "/sentinel/primaries", testPrimariesSecret, true, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 when no secret is configured, even signed", code)
	}
}
