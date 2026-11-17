package sentinel

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// #3515 — the sentinel→backend hop. /certs (which answers with private
// keys), /authorized-keys[/sentinel], the SSH authz requests and the SSH
// session shipper (which carries the audit-ingest bearer) all go to the
// backend daemon's gateway port. Request signatures authenticate the
// sentinel but encrypt nothing. With --backend-tls the hop is TLS verified
// against the pool's peer CA, with the backend ID as the expected name (the
// daemon serves its sentinel-issued peer leaf on that port).
//
// Without it the hop stays plain http this release, with a WARNING on every
// call. A later release flips requireBackendTLSByDefault; plain http then
// needs --backend-insecure-http, which still warns on every call.

// requireBackendTLSByDefault is the default flip: when true, plain http to a
// backend is refused unless BackendTransport.InsecureHTTP is set.
var requireBackendTLSByDefault = false

// BackendTransport is the http.RoundTripper for every sentinel→backend call.
// The zero value is plain http with a warning per call.
type BackendTransport struct {
	TLS          bool                             // --backend-tls
	InsecureHTTP bool                             // --backend-insecure-http
	CAPEM        func() []byte                    // the pool's peer CA; empty fails every TLS call
	Logf         func(format string, args ...any) // nil means log.Printf

	mu    sync.Mutex
	hosts map[string]string          // "ip:port" → backend ID, recorded by BaseURL
	tlsTr map[string]*http.Transport // backend ID → transport pinned to caPEM
	caPEM []byte
	plain *http.Transport
}

// BaseURL returns the scheme://ip:port base of backendID's gateway, or an
// error when plaintext is not allowed.
func (t *BackendTransport) BaseURL(backendID, ip string, port int) (string, error) {
	host := net.JoinHostPort(ip, strconv.Itoa(port))
	if t.TLS {
		t.mu.Lock()
		if t.hosts == nil {
			t.hosts = make(map[string]string)
		}
		t.hosts[host] = backendID
		t.mu.Unlock()
		return "https://" + host, nil
	}
	if requireBackendTLSByDefault && !t.InsecureHTTP {
		return "", fmt.Errorf("plaintext http to backend %q refused: set --backend-tls (or --backend-insecure-http to accept plaintext)", backendID)
	}
	return "http://" + host, nil
}

// Client returns an http.Client over this transport; timeout 0 means none.
func (t *BackendTransport) Client(timeout time.Duration) *http.Client {
	return &http.Client{Transport: t, Timeout: timeout}
}

// RoundTrip implements http.RoundTripper.
func (t *BackendTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		rt, err := t.tlsTransport(req.URL.Host)
		if err != nil {
			return nil, err
		}
		return rt.RoundTrip(req)
	}
	logf := t.Logf
	if logf == nil {
		logf = log.Printf
	}
	logf("[sentinel] WARNING: plaintext http to backend %s for %s; set --backend-tls to verify the backend against the pool's peer CA (#3515)", req.URL.Host, req.URL.Path)
	t.mu.Lock()
	if t.plain == nil {
		t.plain = http.DefaultTransport.(*http.Transport).Clone()
	}
	rt := t.plain
	t.mu.Unlock()
	return rt.RoundTrip(req)
}

// tlsTransport returns host's transport, pinned to the current peer CA and to
// the backend ID as the certificate name. Rebuilt when the CA changes.
func (t *BackendTransport) tlsTransport(host string) (*http.Transport, error) {
	var caPEM []byte
	if t.CAPEM != nil {
		caPEM = t.CAPEM()
	}
	if len(caPEM) == 0 {
		return nil, fmt.Errorf("backend TLS to %s: no peer CA configured on this sentinel", host)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	id, ok := t.hosts[host]
	if !ok {
		return nil, fmt.Errorf("backend TLS to %s: not a known backend address", host)
	}
	if !bytes.Equal(caPEM, t.caPEM) {
		t.caPEM, t.tlsTr = caPEM, make(map[string]*http.Transport)
	}
	if tr, ok := t.tlsTr[id]; ok {
		return tr, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("backend TLS to %s: peer CA is not parseable", host)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: id, MinVersion: tls.VersionTLS12}
	t.tlsTr[id] = tr
	return tr, nil
}

// defaultBackendTransport serves stores that were not given one: plain http
// with the per-call warning.
var defaultBackendTransport = &BackendTransport{}

func orDefaultTransport(t *BackendTransport) *BackendTransport {
	if t == nil {
		return defaultBackendTransport
	}
	return t
}
