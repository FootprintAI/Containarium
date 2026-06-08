package sentinel

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	certsgen "github.com/footprintai/go-certs/pkg/certs/gen"
	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtractSNI_RealClientHello generates a real TLS ClientHello via the
// stdlib's tls.Client and verifies extractSNI parses the SNI field correctly.
func TestExtractSNI_RealClientHello(t *testing.T) {
	cases := []string{
		"prod.example.com",
		"a.b",           // minimal
		"x.example.com", // typical
	}
	for _, sni := range cases {
		t.Run(sni, func(t *testing.T) {
			// Pipe a stdlib TLS handshake into our parser.
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			go func() {
				cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true}
				_ = tls.Client(clientConn, cfg).Handshake() // will fail; we just want bytes
			}()

			br := bufio.NewReaderSize(serverConn, 16389)
			hdr, err := br.Peek(5)
			require.NoError(t, err)
			recLen := int(hdr[3])<<8 | int(hdr[4])
			full, err := br.Peek(5 + recLen)
			require.NoError(t, err)

			got, err := extractSNI(full)
			require.NoError(t, err)
			assert.Equal(t, sni, got)
		})
	}
}

func TestExtractSNI_Errors(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
	}{
		{"empty", nil},
		{"too short for record header", []byte{0x16, 0x03}},
		{"wrong content type", []byte{0x17, 0x03, 0x03, 0x00, 0x00}},
		{"record body truncated", []byte{0x16, 0x03, 0x03, 0x00, 0x10, 0x01}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := extractSNI(tc.buf)
			assert.Error(t, err)
		})
	}
}

// TestSNIRouting_DispatchViaYamux verifies slice 8: a tunnel-promoted
// primary (Primary.BackendID set) is reached via TunnelRegistry.DialTunnel,
// not by TCP-dialing Primary.IP:Port. The IP/Port on the registry entry
// is the sentinel-side loopback alias which often collides with the
// sentinel's own ConnMux; yamux is the correct dispatch path.
func TestSNIRouting_DispatchViaYamux(t *testing.T) {
	primaryAddr, primaryHits := startEchoListener(t, "PRIMARY")
	fallbackAddr, fallbackHits := startEchoListener(t, "FALLBACK")

	// Establish a real yamux session pair: server (primary side) and
	// client (sentinel side). The "primary" side listens for streams,
	// reads the 2-byte port header, then proxies to its echo TLS server.
	primaryConn, sentinelConn := net.Pipe()
	defer primaryConn.Close()
	defer sentinelConn.Close()

	primarySession, err := yamux.Server(primaryConn, nil)
	require.NoError(t, err)
	sentinelSession, err := yamux.Client(sentinelConn, nil)
	require.NoError(t, err)
	defer primarySession.Close()
	defer sentinelSession.Close()

	// Primary side: accept yamux streams, read 2-byte port header,
	// dial localhost:<that port>, bidirectional copy.
	go func() {
		for {
			s, err := primarySession.Accept()
			if err != nil {
				return
			}
			go func(stream net.Conn) {
				defer stream.Close()
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(stream, hdr); err != nil {
					return
				}
				port := int(hdr[0])<<8 | int(hdr[1])
				_, primaryPortStr, _ := net.SplitHostPort(primaryAddr)
				if mustAtoi(t, primaryPortStr) != port {
					return // wrong port → drop
				}
				up, err := net.Dial("tcp", primaryAddr)
				if err != nil {
					return
				}
				defer up.Close()
				done := make(chan struct{}, 2)
				go func() { io.Copy(up, stream); done <- struct{}{} }()
				go func() { io.Copy(stream, up); done <- struct{}{} }()
				<-done
			}(s)
		}
	}()

	// Build the manager with both registries wired in.
	tr := NewTunnelRegistry()
	tr.spots["lab-primary-1"] = &TunnelSpot{
		ID:      "lab-primary-1",
		Session: sentinelSession,
		LocalIP: "127.0.0.99",
	}

	m := &Manager{
		primaries:      NewPrimaryRegistry(),
		tunnelRegistry: tr,
	}
	_, primaryPortStr, _ := net.SplitHostPort(primaryAddr)
	primaryPort := mustAtoi(t, primaryPortStr)

	m.primaries.Register(Primary{
		Pool:      "lab",
		Hostname:  "containarium-lab.example",
		IP:        "127.0.0.99", // sentinel-side loopback alias (intentionally bogus — we use yamux instead)
		Port:      primaryPort,  // primary's side port (matches the echo listener)
		BackendID: "tunnel-lab-primary-1",
	})

	handler := m.buildSNIRoutingHandler(fallbackAddr)

	// Inbound TLS with SNI=containarium-lab.example should route via yamux,
	// not TCP-dial 127.0.0.99 (which has no listener and would fail).
	got := dialThroughHandler(t, handler, &tls.Config{
		ServerName: "containarium-lab.example", InsecureSkipVerify: true,
	})
	assert.Equal(t, "PRIMARY", got, "tunnel-promoted primary should dispatch via yamux")
	assert.Equal(t, 1, primaryHits())
	assert.Equal(t, 0, fallbackHits())

	// Unknown SNI still falls back via TCP dial.
	got = dialThroughHandler(t, handler, &tls.Config{
		ServerName: "stranger.example", InsecureSkipVerify: true,
	})
	assert.Equal(t, "FALLBACK", got)
	assert.Equal(t, 1, fallbackHits())
}

// TestSNIRouting_DispatchToPrimaryOrFallback wires up a fake "primary" TLS
// server and a fake "fallback" TLS server, then drives connections through
// the sentinel's SNI-routing handler. SNI-matched connections (by primary
// hostname or alias) land on the primary; unknown SNIs fall back.
func TestSNIRouting_DispatchToPrimaryOrFallback(t *testing.T) {
	primaryAddr, primaryHits := startEchoListener(t, "PRIMARY")
	fallbackAddr, fallbackHits := startEchoListener(t, "FALLBACK")

	m := &Manager{primaries: NewPrimaryRegistry()}
	primaryHost, primaryPortStr, err := net.SplitHostPort(primaryAddr)
	require.NoError(t, err)
	m.primaries.Register(Primary{
		Pool:     "prod",
		Hostname: "pool-prod.example",
		Aliases:  []string{"app.example"}, // app domain handled by the same primary
		IP:       primaryHost,
		Port:     mustAtoi(t, primaryPortStr),
	})
	handler := m.buildSNIRoutingHandler(fallbackAddr)

	// SNI=pool-prod.example (primary hostname) → primary
	got := dialThroughHandler(t, handler, &tls.Config{
		ServerName: "pool-prod.example", InsecureSkipVerify: true,
	})
	assert.Equal(t, "PRIMARY", got, "primary hostname should land on primary")

	// SNI=app.example (alias) → primary
	got = dialThroughHandler(t, handler, &tls.Config{
		ServerName: "app.example", InsecureSkipVerify: true,
	})
	assert.Equal(t, "PRIMARY", got, "aliased hostname should land on the same primary")

	// SNI not in registry → fallback
	got = dialThroughHandler(t, handler, &tls.Config{
		ServerName: "stranger.example", InsecureSkipVerify: true,
	})
	assert.Equal(t, "FALLBACK", got, "unknown SNI should land on fallback")

	assert.Equal(t, 2, primaryHits(), "primary hostname + alias should both hit the primary")
	assert.Equal(t, 1, fallbackHits())
}

// dialThroughHandler simulates an inbound TLS connection by accepting on a
// throwaway listener and handing the server side to the SNI handler under
// test, while the test goroutine drives the client side.
func dialThroughHandler(t *testing.T, handler func(net.Conn), clientCfg *tls.Config) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		serverConn, err := ln.Accept()
		if err != nil {
			return
		}
		handler(serverConn)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	tlsConn := tls.Client(conn, clientCfg)
	require.NoError(t, tlsConn.Handshake())
	defer tlsConn.Close()

	_, err = tlsConn.Write([]byte("ping\n"))
	require.NoError(t, err)
	buf := make([]byte, 64)
	_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := tlsConn.Read(buf)
	return string(buf[:findFirst(buf[:n], '\n')])
}

// sharedTestCert returns a TLS cert generated once per test package run.
// certsgen.NewTLSCredentials does a full RSA CA+server+client generation,
// which is ~2s; sharing one cert across all listeners keeps the test fast.
var (
	sharedTestCertOnce sync.Once
	sharedTestCertVal  tls.Certificate
	sharedTestCertErr  error
)

func sharedTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	sharedTestCertOnce.Do(func() {
		now := time.Now()
		creds, err := certsgen.NewTLSCredentials(
			now.Add(-time.Hour),
			now.Add(time.Hour),
			certsgen.WithOrganizations("Containarium-Test"),
		)
		if err != nil {
			sharedTestCertErr = err
			return
		}
		sharedTestCertVal, sharedTestCertErr = tls.X509KeyPair(creds.ServerCert.Bytes(), creds.ServerKey.Bytes())
	})
	require.NoError(t, sharedTestCertErr)
	return sharedTestCertVal
}

// startEchoListener starts a TLS server that responds to any read with `tag`
// followed by '\n', regardless of input.
func startEchoListener(t *testing.T, tag string) (addr string, hits func() int) {
	t.Helper()

	cfg := &tls.Config{Certificates: []tls.Certificate{sharedTestCert(t)}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	var (
		mu      sync.Mutex
		hitsVal int
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			hitsVal++
			mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.ReadFull(c, make([]byte, 5))
				_, _ = c.Write([]byte(tag + "\n"))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() int {
		mu.Lock()
		defer mu.Unlock()
		return hitsVal
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	var n int
	for _, ch := range s {
		require.True(t, ch >= '0' && ch <= '9', "non-numeric port")
		n = n*10 + int(ch-'0')
	}
	return n
}

func findFirst(b []byte, ch byte) int {
	for i, c := range b {
		if c == ch {
			return i
		}
	}
	return len(b)
}
