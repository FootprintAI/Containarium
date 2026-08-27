package sentinel

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// #1598: selfCheckProxyPath wrote a SINGLE TLS record-layer byte (0x16) and
// then waited to read a byte back, treating a read timeout as "the proxy
// pipeline is wedged". Three consecutive failures exit the process.
//
// A TLS server handed one byte of a record header does the correct thing:
// it waits for the rest of the ClientHello. It does not respond, and it does
// not EOF — so the probe timed out against a perfectly healthy pipeline,
// and the sentinel killed itself every ~2 minutes. In production both
// sentinels reached NRestarts=43 and 20 within minutes of v0.68.0, and while
// looping they served a self-signed fallback certificate to every visitor.
//
// The probe has to send something a TLS server can actually act on. These
// tests pin that: a real TLS peer must read as healthy, and only a genuine
// wedge (accepts TCP, nothing downstream ever services the connection) may
// be reported as a failure.

// selfCheckManager builds a Manager whose self-check probes the given port.
func selfCheckManager(port int) *Manager {
	return &Manager{config: Config{HTTPSPort: port}}
}

// THE regression: a real TLS server. Under the one-byte probe this timed out,
// because the server was still waiting for the rest of the ClientHello.
func TestSelfCheckProxyPath_HealthyTLSServerIsNotAWedge(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	port := srv.Listener.Addr().(*net.TCPAddr).Port
	m := selfCheckManager(port)

	if err := m.selfCheckProxyPath(5 * time.Second); err != nil {
		t.Fatalf("healthy TLS server reported as wedged (#1598): %v", err)
	}
}

// A genuine wedge must still be caught — that is the whole point of #1512.
// Accepts TCP, never reads, never writes.
func TestSelfCheckProxyPath_WedgedListenerStillDetected(t *testing.T) {
	w := newWedgedListener(t)
	defer func() { _ = w.Close() }()

	m := selfCheckManager(w.port)

	err := m.selfCheckProxyPath(1500 * time.Millisecond)
	if err == nil {
		t.Fatal("a wedged pipeline must be reported as a failure — this is the condition " +
			"the self-check exists to catch (#1512)")
	}
	if !strings.Contains(err.Error(), "unresponsive") {
		t.Errorf("want an 'unresponsive' wedge error, got: %v", err)
	}
}

// A peer that reacts by closing the connection is healthy, not wedged: the
// pipeline demonstrably serviced the connection. This is what an SNI router
// does when it cannot route the requested name.
func TestSelfCheckProxyPath_ImmediateCloseIsHealthy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	m := selfCheckManager(ln.Addr().(*net.TCPAddr).Port)

	if err := m.selfCheckProxyPath(3 * time.Second); err != nil {
		t.Fatalf("a peer that closes the connection reacted, so it is not a wedge: %v", err)
	}
}

// A peer that reads the ClientHello and replies with a TLS alert has also
// reacted. Only a timeout means wedged — an alert is a healthy refusal.
func TestSelfCheckProxyPath_TLSAlertIsHealthy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				// A tls.Server with no certificates reads the ClientHello
				// and answers with a handshake failure alert.
				_ = tls.Server(c, &tls.Config{}).Handshake()
			}(conn)
		}
	}()

	m := selfCheckManager(ln.Addr().(*net.TCPAddr).Port)

	if err := m.selfCheckProxyPath(3 * time.Second); err != nil {
		t.Fatalf("a TLS alert is a reaction, not a wedge: %v", err)
	}
}

// Nothing listening at all is a dial failure, not a pipeline wedge, but it
// must still surface as an error rather than a false pass.
func TestSelfCheckProxyPath_NoListenerIsAnError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // free the port so the dial is refused

	m := selfCheckManager(port)

	if err := m.selfCheckProxyPath(2 * time.Second); err == nil {
		t.Fatal("dialing a closed port must report an error")
	}
}
