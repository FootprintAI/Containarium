package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/version"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// trackBody records whether it was read to EOF and closed, so a test can
// assert drainClose's drain-before-close behaviour.
type trackBody struct {
	r         io.Reader
	readToEOF bool
	closed    bool
}

func (b *trackBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err == io.EOF {
		b.readToEOF = true
	}
	return n, err
}

func (b *trackBody) Close() error {
	b.closed = true
	return nil
}

// TestDrainClose_DrainsThenCloses guards the HTTP/2 hygiene fix
// (FootprintAI/Containarium#422): a response body must be drained to EOF
// before Close so Go doesn't emit a stream-cancelling RST_STREAM/PING that
// a fronting edge (Cloudflare) treats as abusive.
func TestDrainClose_DrainsThenCloses(t *testing.T) {
	body := &trackBody{r: strings.NewReader("unread payload")}
	drainClose(&http.Response{Body: body})
	if !body.readToEOF {
		t.Error("drainClose must read the body to EOF before closing")
	}
	if !body.closed {
		t.Error("drainClose must close the body")
	}
}

// TestDrainClose_NilSafe: drainClose must tolerate a nil response or body
// (some methods return early before assigning resp).
func TestDrainClose_NilSafe(t *testing.T) {
	drainClose(nil)
	drainClose(&http.Response{})
}

// TestNewHTTPClient_PinsHTTP1 is the regression guard for
// FootprintAI/Containarium#422: the REST client must NOT negotiate
// HTTP/2. A long-running container create carried on an HTTP/2
// connection through a fronting TLS edge intermittently resets with
// `remote error: tls: internal error` (the box is provisioned; only the
// response connection dies), while the same request over HTTP/1.1 is
// clean. The fix clears TLSNextProto on a cloned default transport — the
// documented way to force HTTP/1.1 — so this asserts the transport is
// pinned and h2 cannot be auto-enabled.
func TestNewHTTPClient_PinsHTTP1(t *testing.T) {
	c, err := NewHTTPClient("https://example.test", "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	tr, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", c.httpClient.Transport)
	}
	if tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 must be false to keep HTTP/2 off")
	}
	// A non-nil but empty TLSNextProto is what disables HTTP/2 auto-upgrade:
	// net/http only installs the h2 ALPN handler when TLSNextProto is nil.
	if tr.TLSNextProto == nil {
		t.Fatal("TLSNextProto must be non-nil (empty) to disable HTTP/2 auto-upgrade")
	}
	if len(tr.TLSNextProto) != 0 {
		t.Errorf("TLSNextProto must be empty, got %d entries", len(tr.TLSNextProto))
	}
	// Sanity: the cloned default transport must preserve sane dial defaults
	// (not a zero-value transport with no timeouts).
	if tr.DialContext == nil {
		t.Error("expected DialContext preserved from http.DefaultTransport clone")
	}
}

// TestDoRequest_AdvertisesClientVersion guards that every CLI→daemon request
// carries the client version — a conventional User-Agent ("containarium/<ver>")
// plus the explicit X-Containarium-Client-Version header — so a server can log
// or gate on it.
func TestDoRequest_AdvertisesClientVersion(t *testing.T) {
	var gotUA, gotVer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotVer = r.Header.Get(version.ClientVersionHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	resp, err := c.doRequest(context.Background(), http.MethodGet, "/test", nil)
	if err != nil {
		t.Fatalf("doRequest: %v", err)
	}
	drainClose(resp)

	if !strings.HasPrefix(gotUA, "containarium/") {
		t.Errorf("User-Agent = %q; want containarium/<version> prefix", gotUA)
	}
	if gotVer != version.GetVersion() {
		t.Errorf("%s = %q; want %q", version.ClientVersionHeader, gotVer, version.GetVersion())
	}
}

// TestHTTPSetContainerTTL_Success: the client POSTs duration_seconds to
// /v1/containers/{name}/ttl and parses the returned ttl_expires_at. This is
// the keep-on-failure path that #264's TTL-404 left broken (the CLI was a
// client-side stub that never called the endpoint).
func TestHTTPSetContainerTTL_Success(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		// grpc-gateway emits camelCase JSON; protojson accepts it.
		_, _ = w.Write([]byte(`{"ttlExpiresAt":"2030-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	resp, err := c.SetContainerTTL("alice", 3600)
	if err != nil {
		t.Fatalf("SetContainerTTL: %v", err)
	}
	if gotPath != "/v1/containers/alice/ttl" {
		t.Errorf("path = %q; want /v1/containers/alice/ttl", gotPath)
	}
	// JSON numbers decode as float64.
	if gotBody["duration_seconds"] != float64(3600) {
		t.Errorf("duration_seconds = %v; want 3600", gotBody["duration_seconds"])
	}
	if resp.GetTtlExpiresAt() == nil {
		t.Errorf("response ttl_expires_at not parsed")
	}
}

// TestHTTPSetContainerTTL_404IsUnimplemented: a daemon too old to expose the
// endpoint returns 404, which the client maps to codes.Unimplemented so the
// CLI's soft-degrade path fires (Action doesn't hard-fail).
func TestHTTPSetContainerTTL_404IsUnimplemented(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	_, err = c.SetContainerTTL("alice", 3600)
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("404 mapped to %v; want Unimplemented", status.Code(err))
	}
}
