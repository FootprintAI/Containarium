package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// tlsWSPeer is an https peer that accepts a terminal WebSocket upgrade.
func tlsWSPeer(t *testing.T) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = c.Close()
	}))
	t.Cleanup(srv.Close)
	return srv
}

func caPoolOf(srv *httptest.Server) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(srv.Certificate())
	return p
}

// unrelatedCAPool holds a freshly generated CA that signed nothing. (Every
// httptest TLS server shares one built-in cert, so a second server is not a
// different CA.)
func unrelatedCAPool(t *testing.T) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	p := x509.NewCertPool()
	p.AddCert(cert)
	return p
}

// #3516: without pool PKI there is no terminal TLS config (plain ws://).
func TestPeerPool_PeerTerminalTLSConfig_NilWithoutPKI(t *testing.T) {
	pool := NewPeerPool("local", "", nil, "")
	if cfg := pool.PeerTerminalTLSConfig(); cfg != nil {
		t.Fatalf("want nil TLS config without pool PKI, got %+v", cfg)
	}
}

// #3516: with pool PKI the terminal dial verifies the peer against the
// pinned pool CA. The right CA connects over wss://; a wrong CA fails.
func TestPeerPool_PeerTerminalTLSConfig_VerifiesPoolCA(t *testing.T) {
	peer := tlsWSPeer(t)
	wssURL := "wss://" + peer.Listener.Addr().String() + "/v1/containers/alice/terminal"

	for _, tc := range []struct {
		name    string
		ca      *x509.CertPool
		wantErr bool
	}{
		{"pool CA", caPoolOf(peer), false},
		{"wrong CA", unrelatedCAPool(t), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := NewPeerPool("local", "", nil, "")
			pool.pki = &peerPKI{caPool: tc.ca}
			cfg := pool.PeerTerminalTLSConfig()
			if cfg == nil {
				t.Fatal("want a TLS config with pool PKI, got nil")
			}
			d := websocket.Dialer{TLSClientConfig: cfg}
			c, _, err := d.Dial(wssURL, nil)
			if tc.wantErr {
				if err == nil {
					_ = c.Close()
					t.Fatal("dial with a wrong CA succeeded; want a certificate error")
				}
				if !strings.Contains(err.Error(), "certificate") {
					t.Fatalf("want a certificate error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("dial with the pool CA failed: %v", err)
			}
			_ = c.Close()
		})
	}
}
