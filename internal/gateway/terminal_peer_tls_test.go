package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/gorilla/websocket"
)

// tlsPeerProxy returns a fixed peer URL and the TLS config to dial it with,
// as PeerPool does when pool mTLS is on.
type tlsPeerProxy struct {
	url string
	cfg *tls.Config
}

func (p tlsPeerProxy) PeerTerminalURL(string, string) (string, error) { return p.url, nil }
func (p tlsPeerProxy) PeerTerminalTLSConfig() *tls.Config             { return p.cfg }

// peerHit records what the peer saw on its terminal endpoint.
type peerHit struct {
	tls    bool
	bearer bool
}

func wsPeer(t *testing.T, useTLS bool) (*httptest.Server, chan peerHit) {
	t.Helper()
	hits := make(chan peerHit, 1)
	up := websocket.Upgrader{Subprotocols: []string{auth.WSSubprotocolBearer}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- peerHit{
			tls:    r.TLS != nil,
			bearer: strings.Contains(r.Header.Get("Sec-WebSocket-Protocol"), "peer-token"),
		}
		if c, err := up.Upgrade(w, r, nil); err == nil {
			_ = c.Close()
		}
	})
	var srv *httptest.Server
	if useTLS {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	return srv, hits
}

func poolOf(srv *httptest.Server) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(srv.Certificate())
	return p
}

// unrelatedCAPool is a pool holding a freshly generated CA that signed
// nothing. (Every httptest TLS server shares one built-in cert, so a second
// server is not a different CA.)
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

func peerTerminalRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/containers/alice/terminal", nil)
	r.Header.Set("Sec-WebSocket-Protocol", auth.WSSubprotocolBearer+", peer-token")
	return r
}

// #3516: a wss:// peer is dialled over TLS with the proxy's pinned CA, so
// the bearer and terminal I/O never cross the pool in plaintext; a peer
// whose cert is not from that CA is refused.
func TestHandleTerminal_PeerWSS_VerifiesPoolCA(t *testing.T) {
	peer, hits := wsPeer(t, true)
	wssURL := "wss://" + peer.Listener.Addr().String() + "/v1/containers/alice/terminal"

	t.Run("pool CA", func(t *testing.T) {
		th := &TerminalHandler{upgrader: newTerminalUpgrader()}
		th.SetPeerProxy(tlsPeerProxy{url: wssURL, cfg: &tls.Config{RootCAs: poolOf(peer), MinVersion: tls.VersionTLS12}})
		rec := httptest.NewRecorder()
		th.HandleTerminal(rec, peerTerminalRequest())
		if rec.Code == http.StatusBadGateway {
			t.Fatalf("dial with the pool CA failed: %q", rec.Body.String())
		}
		select {
		case h := <-hits:
			if !h.tls {
				t.Fatal("peer saw a plaintext connection; want TLS")
			}
			if !h.bearer {
				t.Fatal("peer did not receive the bearer subprotocol")
			}
		default:
			t.Fatal("the peer was never reached")
		}
	})

	t.Run("wrong CA", func(t *testing.T) {
		th := &TerminalHandler{upgrader: newTerminalUpgrader()}
		th.SetPeerProxy(tlsPeerProxy{url: wssURL, cfg: &tls.Config{RootCAs: unrelatedCAPool(t), MinVersion: tls.VersionTLS12}})
		rec := httptest.NewRecorder()
		th.HandleTerminal(rec, peerTerminalRequest())
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadGateway, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "certificate") {
			t.Fatalf("want a certificate error, got %q", rec.Body.String())
		}
		select {
		case <-hits:
			t.Fatal("the peer handler ran despite an unverified certificate")
		default:
		}
	})
}

// #3516: a plain-http peer keeps ws:// and still connects.
func TestHandleTerminal_PeerWS_PlainStillWorks(t *testing.T) {
	peer, hits := wsPeer(t, false)
	th := &TerminalHandler{upgrader: newTerminalUpgrader()}
	th.SetPeerProxy(tlsPeerProxy{url: "ws://" + peer.Listener.Addr().String() + "/v1/containers/alice/terminal"})
	rec := httptest.NewRecorder()
	th.HandleTerminal(rec, peerTerminalRequest())
	if rec.Code == http.StatusBadGateway {
		t.Fatalf("plain ws dial failed: %q", rec.Body.String())
	}
	select {
	case h := <-hits:
		if h.tls {
			t.Fatal("plain peer unexpectedly saw TLS")
		}
	default:
		t.Fatal("the peer was never reached")
	}
}
