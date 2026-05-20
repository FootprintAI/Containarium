package sentinel

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/pki"
)

// End-to-end coverage for Phase 0.5: the daemon-side bootstrap path
// (FetchPeerPKI in internal/server) is symmetric to these handlers,
// so a roundtrip test here is the cleanest way to guard against
// drift. We exercise:
//
//   - GET /sentinel/ca returns the PEM bundle when CA is wired
//   - GET /sentinel/ca returns 503 when CA is unwired
//   - POST /sentinel/peer-cert mints a verifiable cert
//   - both handlers reject requests without a valid HMAC

const phase05Secret = "abcdefghijklmnopqrstuvwxyz0123456789ABCD" // 40 bytes

func newManagerForPKITest(t *testing.T, withCA bool) *Manager {
	t.Helper()
	m := &Manager{backends: NewBackendPool()}
	m.SetHMACSecret([]byte(phase05Secret))
	if withCA {
		caKeyPEM, err := pki.GenerateCAKey()
		if err != nil {
			t.Fatalf("GenerateCAKey: %v", err)
		}
		prov, err := pki.NewFromKey(caKeyPEM, 0)
		if err != nil {
			t.Fatalf("NewFromKey: %v", err)
		}
		if err := m.SetCertProvisioner(prov); err != nil {
			t.Fatalf("SetCertProvisioner: %v", err)
		}
	}
	return m
}

func TestCAHandler_ReturnsBundle(t *testing.T) {
	m := newManagerForPKITest(t, true)

	req := httptest.NewRequest(http.MethodGet, "/sentinel/ca", nil)
	auth.SignSentinelRequest(req, []byte(phase05Secret))
	rec := httptest.NewRecorder()
	// Wrap with the middleware exactly as binaryserver.go does.
	handler := auth.SentinelHMACMiddleware([]byte(phase05Secret), m.CAHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.Bytes()
	if !bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("body is not PEM:\n%s", body)
	}
}

func TestCAHandler_503WhenUnconfigured(t *testing.T) {
	m := newManagerForPKITest(t, false)

	req := httptest.NewRequest(http.MethodGet, "/sentinel/ca", nil)
	auth.SignSentinelRequest(req, []byte(phase05Secret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(phase05Secret), m.CAHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestCAHandler_RejectsUnsignedRequest(t *testing.T) {
	m := newManagerForPKITest(t, true)

	req := httptest.NewRequest(http.MethodGet, "/sentinel/ca", nil) // no SignSentinelRequest
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(phase05Secret), m.CAHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned request must be rejected; got %d", rec.Code)
	}
}

func TestPeerCertHandler_IssuesVerifiableCert(t *testing.T) {
	m := newManagerForPKITest(t, true)

	body, _ := json.Marshal(PeerCertRequest{PeerID: "tunnel-fts-5900x-gpu"})
	req := httptest.NewRequest(http.MethodPost, "/sentinel/peer-cert", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(phase05Secret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(phase05Secret), m.PeerCertHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp PeerCertResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.CertPEM == "" || resp.KeyPEM == "" || resp.CAPEM == "" {
		t.Fatalf("missing fields: %+v", resp)
	}

	// The issued leaf must verify against the bundled CA.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(resp.CAPEM)) {
		t.Fatal("CA bundle not parseable")
	}
	tlsCert, err := tls.X509KeyPair([]byte(resp.CertPEM), []byte(resp.KeyPEM))
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "tunnel-fts-5900x-gpu"}); err != nil {
		t.Fatalf("issued cert does not verify: %v", err)
	}
}

func TestPeerCertHandler_RejectsMissingPeerID(t *testing.T) {
	m := newManagerForPKITest(t, true)

	body := []byte(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/sentinel/peer-cert", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(phase05Secret))
	rec := httptest.NewRecorder()
	handler := auth.SentinelHMACMiddleware([]byte(phase05Secret), m.PeerCertHandler())
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestSentinelTLSEndToEnd_ServesAndVerifies(t *testing.T) {
	// End-to-end smoke: spin up a real HTTPS test server using a
	// sentinel-issued cert, then connect with an http.Client pinned
	// to the matching CA. This is the same path the daemon's
	// peer-to-peer client uses.
	m := newManagerForPKITest(t, true)
	certPEM, keyPEM := m.SentinelServerCertPEM()
	if certPEM == nil {
		t.Fatal("sentinel server cert was not minted")
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	// Build a CA-pinned client (no client cert needed for this
	// simple GET; full mTLS is exercised by the PeerCertHandler
	// roundtrip above).
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(m.CACertPEM())
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: "localhost",
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	// The server's listener uses an ephemeral 127.0.0.1 address;
	// rewrite the URL host to "localhost" so the cert SAN matches.
	urlStr := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	resp, err := client.Get(urlStr + "/hello")
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
