package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

func newTestProvisioner(t *testing.T, expiry time.Duration) *Provisioner {
	t.Helper()
	keyPEM, err := GenerateCAKey()
	if err != nil {
		t.Fatalf("GenerateCAKey: %v", err)
	}
	p, err := NewFromKey(keyPEM, expiry)
	if err != nil {
		t.Fatalf("NewFromKey: %v", err)
	}
	return p
}

func TestIssuedPeerCert_VerifiesAgainstCA(t *testing.T) {
	p := newTestProvisioner(t, 24*time.Hour)
	certPEM, keyPEM, err := p.IssuePeerCert("tunnel-node-a-gpu", nil, nil)
	if err != nil {
		t.Fatalf("IssuePeerCert: %v", err)
	}

	// Build a fresh CA pool with just our CA, then verify the leaf.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(p.CACertPEM()) {
		t.Fatal("AppendCertsFromPEM(CA): no certs added")
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSName:   "tunnel-node-a-gpu",
	}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("verify against CA: %v", err)
	}
}

func TestIssuedPeerCert_WrongPeerIDFails(t *testing.T) {
	p := newTestProvisioner(t, 24*time.Hour)
	certPEM, _, err := p.IssuePeerCert("tunnel-real", nil, nil)
	if err != nil {
		t.Fatalf("IssuePeerCert: %v", err)
	}
	leaf := parseLeaf(t, certPEM)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p.CACertPEM())

	// SAN check rejects a peer impersonating a different ID.
	opts := x509.VerifyOptions{
		Roots:   pool,
		DNSName: "tunnel-attacker",
	}
	if _, err := leaf.Verify(opts); err == nil {
		t.Fatal("verify must reject when SAN does not match expected peer ID")
	}
}

func TestIssuedPeerCert_ForeignCARejected(t *testing.T) {
	p1 := newTestProvisioner(t, 24*time.Hour)
	p2 := newTestProvisioner(t, 24*time.Hour)

	certPEM, _, err := p2.IssuePeerCert("tunnel-a", nil, nil)
	if err != nil {
		t.Fatalf("IssuePeerCert: %v", err)
	}
	leaf := parseLeaf(t, certPEM)

	// Verify against p1's CA — must fail since p2 signed it.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p1.CACertPEM())

	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "tunnel-a"}); err == nil {
		t.Fatal("leaf signed by a different CA must not verify")
	}
}

func TestIssuedPeerCert_ExpiryEnforced(t *testing.T) {
	// Sub-second expiry — by the time we verify, the cert is past
	// NotAfter and chain validation should refuse it.
	p := newTestProvisioner(t, 100*time.Millisecond)
	certPEM, _, err := p.IssuePeerCert("tunnel-a", nil, nil)
	if err != nil {
		t.Fatalf("IssuePeerCert: %v", err)
	}
	leaf := parseLeaf(t, certPEM)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p.CACertPEM())

	time.Sleep(150 * time.Millisecond)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "tunnel-a"}); err == nil {
		t.Fatal("expired cert must not verify")
	}
}

func TestIssueSentinelServerCert_VerifiesAgainstCA(t *testing.T) {
	p := newTestProvisioner(t, 24*time.Hour)
	certPEM, _, err := p.IssueSentinelServerCert(
		[]string{"sentinel.example.com"},
		[]net.IP{net.ParseIP("10.0.0.1")},
	)
	if err != nil {
		t.Fatalf("IssueSentinelServerCert: %v", err)
	}
	leaf := parseLeaf(t, certPEM)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p.CACertPEM())

	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:   "sentinel.example.com",
	}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("verify sentinel cert: %v", err)
	}
}

func TestNewFromKey_RejectsGarbage(t *testing.T) {
	if _, err := NewFromKey([]byte("not a key"), 0); err == nil {
		t.Fatal("garbage input must be rejected")
	}
	if _, err := NewFromKey(nil, 0); err == nil {
		t.Fatal("nil input must be rejected")
	}
}

func TestNewFromKey_DefaultExpiry(t *testing.T) {
	keyPEM, err := GenerateCAKey()
	if err != nil {
		t.Fatalf("GenerateCAKey: %v", err)
	}
	p, err := NewFromKey(keyPEM, 0)
	if err != nil {
		t.Fatalf("NewFromKey: %v", err)
	}
	if p.LeafExpiry() != DefaultLeafExpiry {
		t.Fatalf("LeafExpiry = %v, want default %v", p.LeafExpiry(), DefaultLeafExpiry)
	}
}

func parseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return leaf
}
