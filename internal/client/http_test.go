package client

import (
	"net/http"
	"testing"
)

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
