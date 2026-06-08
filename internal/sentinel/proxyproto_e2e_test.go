package sentinel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProxyProtocolE2E proves the full client-IP-propagation chain:
//
//	test client (127.0.0.1:<known port>)
//	   └─ TLS+SNI ─▶ sentinel SNI router (raw TCP forward + optional PROXY v2 header)
//	                   └─ TCP ─▶ backend (proxyproto.Listener → tls.Listener → http.Server)
//
// The backend's HTTP handler echoes r.RemoteAddr. With the flag on, the
// echoed RemoteAddr must match the test client's source port (proving the
// PROXY header carried the real client identity through). With the flag off,
// it must NOT match — the backend sees whatever ephemeral port the sentinel
// used to dial it.
//
// We distinguish "real client" from "sentinel-as-client" purely by source
// port: the test runs on loopback, but the kernel picks a unique port for
// each TCP socket, so the client's source port is a reliable identifier.
func TestProxyProtocolE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Run("with_proxy_protocol_real_client_ip_reaches_backend", func(t *testing.T) {
		runProxyProtoE2E(t, true)
	})

	t.Run("without_proxy_protocol_backend_sees_sentinel_ip", func(t *testing.T) {
		runProxyProtoE2E(t, false)
	})
}

func runProxyProtoE2E(t *testing.T, useProxyProto bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const sni = "e2e.test.local"

	// ---------------------------------------------------------------
	// 1. Start the backend: proxyproto.Listener → tls.Listener → http
	// ---------------------------------------------------------------

	rawBackendLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = rawBackendLn.Close() }()
	backendAddr := rawBackendLn.Addr().(*net.TCPAddr)

	// We always wrap the backend with proxyproto.Listener using the default
	// USE policy. This is the realistic configuration: Caddy's
	// proxy_protocol listener wrapper does the same. With USE:
	//   - PROXY header present → conn.RemoteAddr() = parsed source
	//   - PROXY header absent  → conn.RemoteAddr() = the actual TCP peer
	// So the assertion changes between the two scenarios but the backend
	// configuration stays identical, which mirrors how production rolls
	// out (deploy backend first, then flip sentinel flag).
	ppLn := &proxyproto.Listener{Listener: rawBackendLn}

	cert, err := generateSelfSignedCert()
	require.NoError(t, err)
	tlsLn := tls.NewListener(ppLn, &tls.Config{Certificates: []tls.Certificate{cert}})

	// echoed back from the handler so the test can parse it
	var seenRemote atomic.Value // string

	backendSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenRemote.Store(r.RemoteAddr)
			fmt.Fprintf(w, "remote=%s\n", r.RemoteAddr)
		}),
	}
	go func() { _ = backendSrv.Serve(tlsLn) }()
	defer func() { _ = backendSrv.Shutdown(ctx) }()

	// ---------------------------------------------------------------
	// 2. Build a Manager with the SNI router pointing at the backend
	// ---------------------------------------------------------------

	primaries := NewPrimaryRegistry()
	primaries.Register(Primary{
		Pool:     "e2e",
		Hostname: sni,
		IP:       "127.0.0.1",
		Port:     backendAddr.Port,
	})
	m := &Manager{
		config:    Config{ProxyProtocol: useProxyProto},
		primaries: primaries,
		// backends/certStore/keyStore unused by buildSNIRoutingHandler
	}

	sentinelLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = sentinelLn.Close() }()
	sentinelAddr := sentinelLn.Addr().(*net.TCPAddr)

	// fallbackTarget is a dead address — should never be hit because the
	// SNI matches a registered primary.
	handler := m.buildSNIRoutingHandler("127.0.0.1:1")

	go func() {
		for {
			c, err := sentinelLn.Accept()
			if err != nil {
				return
			}
			go handler(c)
		}
	}()

	// ---------------------------------------------------------------
	// 3. Connect from a known client source port
	// ---------------------------------------------------------------

	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		Timeout:   3 * time.Second,
	}
	rawClient, err := dialer.Dial("tcp", sentinelAddr.String())
	require.NoError(t, err)
	defer func() { _ = rawClient.Close() }()

	clientLocal := rawClient.LocalAddr().(*net.TCPAddr)
	t.Logf("[e2e] client source = %s, sentinel = %s, backend = %s, proxy_protocol=%v",
		clientLocal, sentinelAddr, backendAddr, useProxyProto)

	// TLS handshake — the sentinel SNI-routes the ClientHello to backend,
	// which terminates TLS.
	tlsClient := tls.Client(rawClient, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
	})
	_ = rawClient.SetDeadline(time.Now().Add(5 * time.Second))
	require.NoError(t, tlsClient.Handshake(), "TLS handshake through sentinel must succeed")

	// HTTP/1.1 GET — minimal hand-rolled request so we keep the connection
	// in our control.
	_, err = fmt.Fprintf(tlsClient,
		"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sni)
	require.NoError(t, err)

	respBytes, err := io.ReadAll(tlsClient)
	require.NoError(t, err)
	resp := string(respBytes)
	t.Logf("[e2e] response:\n%s", resp)

	// Extract `remote=<addr>` from the body.
	idx := strings.Index(resp, "remote=")
	require.NotEqual(t, -1, idx, "handler did not echo remote address; full response:\n%s", resp)
	rest := resp[idx+len("remote="):]
	if nl := strings.IndexAny(rest, "\r\n"); nl >= 0 {
		rest = rest[:nl]
	}
	seenAddr, err := net.ResolveTCPAddr("tcp", rest)
	require.NoError(t, err, "could not parse echoed remote %q", rest)

	// ---------------------------------------------------------------
	// 4. The actual proof
	// ---------------------------------------------------------------

	if useProxyProto {
		assert.Equal(t, clientLocal.Port, seenAddr.Port,
			"with --proxy-protocol the backend MUST see the real client port (got %d, want %d). "+
				"Without this assertion passing, containers cannot identify the requester.",
			seenAddr.Port, clientLocal.Port)
		t.Logf("[e2e] ✓ backend correctly received real client IP: %s", seenAddr)
	} else {
		assert.NotEqual(t, clientLocal.Port, seenAddr.Port,
			"without --proxy-protocol the backend should NOT see the real client port "+
				"(both are %d — the flag may not actually be gating behavior).",
			clientLocal.Port)
		t.Logf("[e2e] ✓ baseline: backend saw sentinel-as-client %s (real client was %s)",
			seenAddr, clientLocal)
	}
}
