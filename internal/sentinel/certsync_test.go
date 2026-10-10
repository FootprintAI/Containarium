package sentinel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/gateway"
)

// testCertPair returns a PEM cert/key pair whose CommonName is domain.
func testCertPair(t *testing.T, domain string) gateway.CertPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return gateway.CertPair{
		Domain:  domain,
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
	}
}

// certsBackend serves body verbatim on /certs and returns its host and port.
func certsBackend(t *testing.T, body string) (string, int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return host, port
}

func certsBody(t *testing.T, pairs ...gateway.CertPair) string {
	t.Helper()
	b, err := json.Marshal(gateway.CertsResponse{Certs: pairs})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func servedLeafCN(t *testing.T, cs *CertStore, sni string) string {
	t.Helper()
	cert, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
	if err != nil {
		t.Fatalf("GetCertificate(%q): %v", sni, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf.Subject.CommonName
}

// seededStore returns a store holding one synced cert for domain.
func seededStore(t *testing.T, domain string) *CertStore {
	t.Helper()
	cs := NewCertStore()
	host, port := certsBackend(t, certsBody(t, testCertPair(t, domain)))
	if err := cs.Sync(host, port); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	if got := cs.SyncedCount(); got != 1 {
		t.Fatalf("seed: synced count = %d, want 1", got)
	}
	return cs
}

func TestCertSync_EmptyResponseKeepsStore(t *testing.T) {
	for _, body := range []string{`{"certs":[]}`, `{}`, `{"certs":null}`} {
		t.Run(body, func(t *testing.T) {
			cs := seededStore(t, "app.example.com")
			host, port := certsBackend(t, body)
			_ = cs.Sync(host, port)

			if got := cs.SyncedCount(); got != 1 {
				t.Fatalf("synced count after empty response = %d, want 1", got)
			}
			if !cs.HasSyncedCerts() {
				t.Fatal("HasSyncedCerts = false after empty response")
			}
			if cn := servedLeafCN(t, cs, "app.example.com"); cn != "app.example.com" {
				t.Fatalf("served cert CN = %q, want app.example.com", cn)
			}
		})
	}
}

func TestCertSync_MalformedResponseKeepsStore(t *testing.T) {
	cases := []struct{ name, body string }{
		{"not json", `<html>oops</html>`},
		{"truncated json", `{"certs":[{"domain":"a`},
		{"unparseable pems", `{"certs":[{"domain":"app.example.com","cert_pem":"x","key_pem":"y"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := seededStore(t, "app.example.com")
			host, port := certsBackend(t, tc.body)
			if err := cs.Sync(host, port); err == nil {
				t.Fatal("Sync returned nil for a malformed response")
			}
			if got := cs.SyncedCount(); got != 1 {
				t.Fatalf("synced count after malformed response = %d, want 1", got)
			}
			if cn := servedLeafCN(t, cs, "app.example.com"); cn != "app.example.com" {
				t.Fatalf("served cert CN = %q, want app.example.com", cn)
			}
		})
	}
}

func TestCertSync_NonEmptyResponseStillReplaces(t *testing.T) {
	cs := seededStore(t, "old.example.com")
	host, port := certsBackend(t, certsBody(t, testCertPair(t, "new.example.com")))
	if err := cs.Sync(host, port); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got := cs.SyncedCount(); got != 1 {
		t.Fatalf("synced count = %d, want 1", got)
	}
	if cn := servedLeafCN(t, cs, "new.example.com"); cn != "new.example.com" {
		t.Fatalf("served cert CN = %q, want new.example.com", cn)
	}
}
