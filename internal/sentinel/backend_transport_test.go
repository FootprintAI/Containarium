package sentinel

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/footprintai/containarium/pkg/core/pki"
)

// #3515: the sentinel's calls to a backend daemon (/certs, /authorized-keys,
// SSH authz and the session shipper) go over TLS verified against the pool's
// peer CA when backend TLS is on, and over plain http with a warning on every
// call otherwise.

func newTestPeerCA(t *testing.T) *pki.Provisioner {
	t.Helper()
	key, err := pki.GenerateCAKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.NewFromKey(key, 0)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// startBackend serves body. With ca set it serves TLS with the peer leaf ca
// issues for leafID (what a daemon holds once peer PKI is up) and refuses
// plaintext; with ca nil it serves plain http.
func startBackend(t *testing.T, ca *pki.Provisioner, leafID, body string) (string, int) {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ca != nil && r.TLS == nil {
			http.Error(w, "plaintext", http.StatusTeapot)
			return
		}
		_, _ = fmt.Fprint(w, body)
	})
	var srv *httptest.Server
	if ca == nil {
		srv = httptest.NewServer(h)
	} else {
		certPEM, keyPEM, err := ca.IssuePeerCert(leafID, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		kp, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		srv = httptest.NewUnstartedServer(h)
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{kp}, MinVersion: tls.VersionTLS12}
		srv.StartTLS()
	}
	t.Cleanup(srv.Close)
	host, p, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(p)
	return host, port
}

type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (l *logCapture) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logCapture) count(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, line := range l.lines {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

const plaintextWarning = "WARNING: plaintext http to backend"

func getVia(tr *BackendTransport, backendID, ip string, port int) error {
	base, err := tr.BaseURL(backendID, ip, port)
	if err != nil {
		return err
	}
	resp, err := tr.Client(0).Get(base + "/certs")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func TestBackendTransport_TLS(t *testing.T) {
	ca, other := newTestPeerCA(t), newTestPeerCA(t)
	ip, port := startBackend(t, ca, "be-1", `{}`)
	for _, tc := range []struct {
		name    string
		id      string
		caPEM   func() []byte
		wantErr string // "" means the call succeeds
	}{
		{"verified against the peer CA", "be-1", ca.CACertPEM, ""},
		{"wrong CA", "be-1", other.CACertPEM, "certificate"},
		{"missing CA", "be-1", func() []byte { return nil }, "no peer CA"},
		{"leaf of another backend", "be-2", ca.CACertPEM, "certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &logCapture{}
			tr := &BackendTransport{TLS: true, CAPEM: tc.caPEM, Logf: logs.logf}
			err := getVia(tr, tc.id, ip, port)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("verified TLS call failed: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
			}
			if n := logs.count(plaintextWarning); n != 0 {
				t.Fatalf("TLS call logged %d plaintext warnings", n)
			}
		})
	}
}

func TestBackendTransport_PlainHTTPWarnsOnEveryCall(t *testing.T) {
	ip, port := startBackend(t, nil, "", `{}`)
	logs := &logCapture{}
	tr := &BackendTransport{Logf: logs.logf}
	for i := 0; i < 2; i++ {
		if err := getVia(tr, "be-1", ip, port); err != nil {
			t.Fatalf("plain http call %d: %v", i, err)
		}
	}
	if n := logs.count(plaintextWarning); n != 2 {
		t.Fatalf("plaintext warnings = %d, want one per call (2); logs %q", n, logs.lines)
	}
}

// Once the default flips (a later release), plaintext needs the explicit
// insecure opt-in, and still warns on every call.
func TestBackendTransport_InsecureOptInOnceDefaultFlips(t *testing.T) {
	prev := requireBackendTLSByDefault
	requireBackendTLSByDefault = true
	t.Cleanup(func() { requireBackendTLSByDefault = prev })

	ip, port := startBackend(t, nil, "", `{}`)
	logs := &logCapture{}
	if err := getVia(&BackendTransport{Logf: logs.logf}, "be-1", ip, port); err == nil || !strings.Contains(err.Error(), "--backend-insecure-http") {
		t.Fatalf("plaintext without opt-in: err = %v, want a refusal naming --backend-insecure-http", err)
	}
	if err := getVia(&BackendTransport{InsecureHTTP: true, Logf: logs.logf}, "be-1", ip, port); err != nil {
		t.Fatalf("plaintext with opt-in: %v", err)
	}
	if n := logs.count(plaintextWarning); n != 1 {
		t.Fatalf("plaintext warnings with opt-in = %d, want 1", n)
	}
}

// The callers named in #3515 go through the transport: a wrong CA fails each.

func TestBackendCallers_UseBackendTLS(t *testing.T) {
	ca, other := newTestPeerCA(t), newTestPeerCA(t)
	for _, tc := range []struct {
		name string
		body string
		call func(tr *BackendTransport, ip string, port int) error
	}{
		{"cert sync", `{"certs":[]}`, func(tr *BackendTransport, ip string, port int) error {
			cs := NewCertStore()
			cs.SetTransport(tr)
			return cs.Sync("be-1", ip, port)
		}},
		{"key sync", `{"keys":[]}`, func(tr *BackendTransport, ip string, port int) error {
			ks := NewKeyStore()
			ks.SetTransport(tr)
			return ks.Sync("be-1", ip, port)
		}},
		{"shipper and SSH authz", `{}`, func(tr *BackendTransport, ip string, port int) error {
			m := &Manager{backends: NewBackendPool(), config: Config{HealthPort: port}, backendTransport: tr}
			m.backends.Add(&Backend{ID: "be-1", IP: ip})
			base, err := m.ShipperBackendURL("be-1")
			if err != nil {
				return err
			}
			if !strings.HasPrefix(base, "https://") {
				return fmt.Errorf("ShipperBackendURL = %q, want https", base)
			}
			resp, err := m.BackendHTTPClient(0).Get(base + "/v1/ssh/authorize")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("status %d", resp.StatusCode)
			}
			return nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip, port := startBackend(t, ca, "be-1", tc.body)
			if err := tc.call(&BackendTransport{TLS: true, CAPEM: ca.CACertPEM}, ip, port); err != nil {
				t.Fatalf("over verified TLS: %v", err)
			}
			if err := tc.call(&BackendTransport{TLS: true, CAPEM: other.CACertPEM}, ip, port); err == nil {
				t.Fatal("succeeded with the wrong CA")
			}
		})
	}
}
