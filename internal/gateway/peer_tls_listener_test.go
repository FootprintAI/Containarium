package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/pki"
)

// #3515: the daemon serves its sentinel-issued peer leaf on the gateway port,
// so the sentinel reaches /certs and friends over verified TLS, while plain
// http callers on the same port keep working.

func serveWithPeerTLS(t *testing.T, cert func() *tls.Certificate) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(NewPeerTLSListener(lis, cert)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return lis.Addr().String()
}

func peerTLSGet(c *http.Client, url string) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func TestPeerTLSListener_ServesTLSAndPlainOnOnePort(t *testing.T) {
	key, err := pki.GenerateCAKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.NewFromKey(key, 0)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssuePeerCert("be-1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	addr := serveWithPeerTLS(t, func() *tls.Certificate { return &kp })

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CACertPEM())
	tlsClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "be-1", MinVersion: tls.VersionTLS12},
	}}
	if body, err := peerTLSGet(tlsClient, "https://"+addr+"/certs"); err != nil || body != "ok" {
		t.Fatalf("verified TLS: body %q err %v", body, err)
	}
	if body, err := peerTLSGet(&http.Client{Timeout: 5 * time.Second}, "http://"+addr+"/certs"); err != nil || body != "ok" {
		t.Fatalf("plain http on the same port: body %q err %v", body, err)
	}
}

// Without a peer leaf (PKI not bootstrapped) a TLS caller fails rather than
// being answered in cleartext, and plain http still works.
func TestPeerTLSListener_NoCertTLSCallFails(t *testing.T) {
	addr := serveWithPeerTLS(t, func() *tls.Certificate { return nil })
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: "be-1", MinVersion: tls.VersionTLS12},
	}}
	if _, err := peerTLSGet(c, "https://"+addr+"/certs"); err == nil {
		t.Fatal("TLS call succeeded with no peer leaf")
	}
	if body, err := peerTLSGet(&http.Client{Timeout: 5 * time.Second}, "http://"+addr+"/certs"); err != nil || body != "ok" {
		t.Fatalf("plain http: body %q err %v", body, err)
	}
}
