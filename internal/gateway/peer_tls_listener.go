package gateway

import (
	"bufio"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
)

// #3515 — the sentinel reaches /certs (certificates and private keys),
// /authorized-keys[/sentinel], SSH authz and session ingest on the gateway
// port. Once the daemon holds its sentinel-issued peer leaf (peer PKI), that
// port also speaks TLS with it, so a sentinel with --backend-tls can verify
// the backend against the pool's peer CA. Plain http on the same port keeps
// working for every other caller: a connection is TLS when its first byte is
// a TLS handshake record.

var peerTLSCert atomic.Pointer[func() *tls.Certificate]

// SetPeerTLSCertificate installs the source of the daemon's peer leaf for the
// gateway port. fn is called on every TLS handshake, so a renewed leaf takes
// effect without a restart; nil refuses TLS on that connection.
func SetPeerTLSCertificate(fn func() *tls.Certificate) { peerTLSCert.Store(&fn) }

func currentPeerTLSCert() *tls.Certificate {
	if fn := peerTLSCert.Load(); fn != nil {
		return (*fn)()
	}
	return nil
}

// NewPeerTLSListener wraps lis so that connections opening with a TLS
// handshake are served TLS with cert(), and every other connection as is.
func NewPeerTLSListener(lis net.Listener, cert func() *tls.Certificate) net.Listener {
	return &peerTLSListener{Listener: lis, cert: cert}
}

type peerTLSListener struct {
	net.Listener
	cert func() *tls.Certificate
}

// Accept does not read: the first byte is peeked on the server's first Read,
// so a slow client never blocks the accept loop.
func (l *peerTLSListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &peerTLSConn{Conn: c, cert: l.cert}, nil
}

type peerTLSConn struct {
	net.Conn
	cert func() *tls.Certificate
	once sync.Once
	rw   net.Conn
}

func (c *peerTLSConn) detect() net.Conn {
	c.once.Do(func() {
		br := bufio.NewReader(c.Conn)
		c.rw = &bufferedConn{Conn: c.Conn, r: br}
		if first, err := br.Peek(1); err == nil && first[0] == 0x16 { // TLS handshake record
			if cert := c.cert(); cert != nil {
				c.rw = tls.Server(c.rw, &tls.Config{
					MinVersion:     tls.VersionTLS12,
					GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil },
				})
			}
		}
	})
	return c.rw
}

func (c *peerTLSConn) Read(p []byte) (int, error)  { return c.detect().Read(p) }
func (c *peerTLSConn) Write(p []byte) (int, error) { return c.detect().Write(p) }

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
