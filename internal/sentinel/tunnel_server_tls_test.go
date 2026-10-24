package sentinel

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startTunnelServer serves ts on a fresh loopback TCP listener and returns
// the address peers dial.
// serveTunnelServer serves ts on ln and registers a cleanup that leaves no
// goroutine of the server behind: it stops Serve, closes the sessions that
// are still registered (which is what ends each monitorSession), and waits
// for every goroutine the server started to exit. Without the wait,
// monitorSession fires after the test returns and writes to the global
// logger and runs `ip addr del` during an unrelated later test, and the
// goroutines pile up across -count repetitions (#3009).
func serveTunnelServer(t *testing.T, ctx context.Context, ts *TunnelServer, ln net.Listener) {
	t.Helper()
	runTunnelServer(t, ctx, ts, func(c context.Context) error { return ts.Serve(c, ln) })
}

// runTunnelServer is serveTunnelServer for a server started by serve, such as
// TunnelServer.Run.
func runTunnelServer(t *testing.T, ctx context.Context, ts *TunnelServer, serve func(context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	served := make(chan struct{})
	go func() { defer close(served); _ = serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-served:
		case <-time.After(10 * time.Second):
			t.Errorf("tunnel server Serve did not return after its context was cancelled")
			return
		}
		// A connection still mid-handshake can register after the first
		// sweep, so keep closing sessions until every goroutine is gone.
		exited := make(chan struct{})
		go func() { ts.Wait(); close(exited) }()
		deadline := time.After(10 * time.Second)
		for {
			ts.registry.UnregisterAll()
			select {
			case <-exited:
				return
			case <-deadline:
				t.Errorf("tunnel server goroutines still running 10s after cleanup")
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	})
}

func startTunnelServer(t *testing.T, ctx context.Context, ts *TunnelServer) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveTunnelServer(t, ctx, ts, ln)
	waitForListener(t, ln.Addr().String())
	return ln.Addr().String()
}

// TestCleartextPeerRefused: a peer that opens with the JSON handshake is
// answered with ok:false and closed before its handshake line is read. The peer only ever sends the opening brace,
// so a server that tried to read the line would hang instead of answering.
// Nothing registers, OnConnect never fires, and the refusal is counted.
func TestCleartextPeerRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	registry := NewTunnelRegistry()
	ts := NewTunnelServer("", policyAny("tok"), registry, 0)
	var connects atomic.Int32
	ts.OnConnect = func(*TunnelSpot) { connects.Add(1) }
	addr := startTunnelServer(t, ctx, ts)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("{"))
	require.NoError(t, err)

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := readHandshakeResponse(conn)
	require.NoError(t, err, "the refusal must arrive without the handshake line being read")
	assert.False(t, resp.OK)
	assert.Equal(t, "tls required; upgrade the tunnel client and set --sentinel-pin", resp.Error)

	// The server closes the connection after the refusal.
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	assert.Error(t, err, "connection must be closed after the refusal")

	assert.Zero(t, registry.Count())
	assert.Zero(t, connects.Load())
	stats := registry.SessionStats()
	assert.Equal(t, uint64(1), stats.CleartextRefused)
	assert.Zero(t, stats.TLS)
}

// TestTunnelServerTLSConfig pins the listener-side transport parameters:
// the identity's certificate, TLS 1.3 only, the tunnel ALPN protocol, and
// no client certificate.
func TestTunnelServerTLSConfig(t *testing.T) {
	id := newTestTunnelIdentity(t)
	cfg := tunnelTLSServerConfig(id)
	require.Len(t, cfg.Certificates, 1)
	assert.Equal(t, id.TLSCertificate().Certificate, cfg.Certificates[0].Certificate)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	assert.Equal(t, []string{TunnelALPN}, cfg.NextProtos)
	assert.Equal(t, tls.NoClientCert, cfg.ClientAuth)
}

// TestTunnelServerRejectsTLSWithoutTunnelALPN: a TLS peer that pins the
// identity but does not offer the tunnel ALPN is not a tunnel client. The
// server closes it without reading a handshake and nothing registers.
func TestTunnelServerRejectsTLSWithoutTunnelALPN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id := newTestTunnelIdentity(t)
	registry := NewTunnelRegistry()
	ts := NewTunnelServer("", policyAny("tok"), registry, 0)
	ts.SetTunnelIdentity(id)
	var connects atomic.Int32
	ts.OnConnect = func(*TunnelSpot) { connects.Add(1) }
	addr := startTunnelServer(t, ctx, ts)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:            "sentinel.example.com",
		MinVersion:            tls.VersionTLS13,
		InsecureSkipVerify:    true, // #nosec G402 -- pinned below, as the tunnel client does
		VerifyPeerCertificate: VerifyPinned([]TunnelPin{id.Pin()}),
	})
	_ = tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	// The handshake may complete (the server only inspects ALPN afterwards)
	// or fail; either way the session must end without a registration.
	_ = tlsConn.Handshake()
	_ = writeHandshake(tlsConn, &TunnelHandshake{Token: "tok", SpotID: "no-alpn", Ports: []int{22}})
	_, err = readHandshakeResponse(tlsConn)
	assert.Error(t, err, "server must close without answering the handshake")

	assert.Zero(t, registry.Count())
	assert.Zero(t, connects.Load())
}

// TestTunnelServerWithoutIdentityClosesTLSPeers: a server that has no tunnel
// identity cannot terminate the TLS transport; it closes such peers rather
// than reading their bytes as a handshake.
func TestTunnelServerWithoutIdentityClosesTLSPeers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	registry := NewTunnelRegistry()
	ts := NewTunnelServer("", policyAny("tok"), registry, 0)
	addr := startTunnelServer(t, ctx, ts)

	client := &TunnelClient{
		SentinelAddr: addr,
		SentinelPins: []TunnelPin{newTestTunnelIdentity(t).Pin()},
		Token:        "tok",
		SpotID:       "s",
		Ports:        []int{22},
	}
	err := client.connectAndServe(ctx)
	require.Error(t, err)
	assert.Zero(t, registry.Count())
}

// TestRenderTunnelMetrics pins the exposition of the tunnel transport
// counters.
func TestRenderTunnelMetrics(t *testing.T) {
	out := renderTunnelMetrics(TunnelSessionStats{TLS: 3, CleartextRefused: 7})
	for _, want := range []string{
		"# TYPE sentinel_tunnel_sessions_tls gauge\n",
		"sentinel_tunnel_sessions_tls 3\n",
		"# TYPE sentinel_tunnel_cleartext_refused_total counter\n",
		"sentinel_tunnel_cleartext_refused_total 7\n",
	} {
		assert.Contains(t, out, want)
	}
}

// TestMetricsAndStatusCarryTunnelSessions: the manager's /metrics and
// /status surfaces show the per-transport session counts from the registry.
func TestMetricsAndStatusCarryTunnelSessions(t *testing.T) {
	stubLoopbackAliases(t)
	registry := NewTunnelRegistry()
	_, _, err := registry.Register(&TunnelHandshake{SpotID: "a", Ports: []int{22}}, nil, TunnelTransportTLS)
	require.NoError(t, err)
	registry.noteCleartextRefused()
	registry.noteCleartextRefused()

	m := NewManager(Config{}, &fakeRecoveryProvider{})
	m.SetTunnelRegistry(registry)

	rec := httptest.NewRecorder()
	m.MetricsHandler()(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	assert.Contains(t, body, "sentinel_tunnel_sessions_tls 1\n")
	assert.NotContains(t, body, "sentinel_tunnel_sessions_cleartext")
	assert.Contains(t, body, "sentinel_tunnel_cleartext_refused_total 2\n")

	rec = httptest.NewRecorder()
	StatusHandler(m)(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	page := rec.Body.String()
	assert.Contains(t, page, "tunnel_sessions_tls")
	assert.True(t, strings.Contains(page, ">1<"), "session counts must be rendered")
}
