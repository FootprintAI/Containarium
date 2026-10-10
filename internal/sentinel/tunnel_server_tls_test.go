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

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startTunnelServer serves ts on a fresh loopback TCP listener and returns
// the address peers dial.
func startTunnelServer(t *testing.T, ctx context.Context, ts *TunnelServer) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = ts.Serve(ctx, ln) }()
	waitForListener(t, ln.Addr().String())
	return ln.Addr().String()
}

// TestCleartextPeerRefused: with cleartext sessions disallowed, a peer that
// opens with the JSON handshake is answered with ok:false and closed before
// its handshake line is read. The peer only ever sends the opening brace,
// so a server that tried to read the line would hang instead of answering.
// Nothing registers, OnConnect never fires, and the refusal is counted.
func TestCleartextPeerRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	registry := NewTunnelRegistry()
	ts := NewTunnelServer("", policyAny("tok"), registry, 0)
	ts.AllowCleartext = false
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
	assert.Contains(t, resp.Error, "tls required")

	// The server closes the connection after the refusal.
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	assert.Error(t, err, "connection must be closed after the refusal")

	assert.Zero(t, registry.Count())
	assert.Zero(t, connects.Load())
	stats := registry.SessionStats()
	assert.Equal(t, uint64(1), stats.CleartextRefused)
	assert.Zero(t, stats.TLS)
	assert.Zero(t, stats.Cleartext)
}

// TestCleartextPeerAcceptedWhenAllowed pins the transition behaviour: with
// cleartext sessions allowed (the constructor default) the legacy JSON
// handshake still registers, and the spot is tagged as a cleartext session.
func TestCleartextPeerAcceptedWhenAllowed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stubLoopbackAliases(t)

	registry := NewTunnelRegistry()
	ts := NewTunnelServer("", policyAny("tok"), registry, 0)
	require.True(t, ts.AllowCleartext, "cleartext sessions are allowed by default during the transition")
	connectCh := make(chan *TunnelSpot, 1)
	ts.OnConnect = func(spot *TunnelSpot) {
		select {
		case connectCh <- spot:
		default:
		}
	}
	addr := startTunnelServer(t, ctx, ts)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, writeHandshake(conn, &TunnelHandshake{Token: "tok", SpotID: "legacy-spot", Ports: []int{22}}))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := readHandshakeResponse(conn)
	require.NoError(t, err)
	require.True(t, resp.OK, "error: %s", resp.Error)
	_ = conn.SetReadDeadline(time.Time{})
	session, err := yamux.Server(conn, nil)
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	select {
	case spot := <-connectCh:
		assert.Equal(t, "legacy-spot", spot.ID)
		assert.Equal(t, TunnelTransportCleartext, spot.Transport)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for the cleartext registration")
	}
	assert.Equal(t, TunnelTransportCleartext, registry.Get("legacy-spot").Transport)
	stats := registry.SessionStats()
	assert.Equal(t, 1, stats.Cleartext)
	assert.Zero(t, stats.TLS)
	assert.Zero(t, stats.CleartextRefused)
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
	out := renderTunnelMetrics(TunnelSessionStats{TLS: 3, Cleartext: 1, CleartextRefused: 7})
	for _, want := range []string{
		"# TYPE sentinel_tunnel_sessions_tls gauge\n",
		"sentinel_tunnel_sessions_tls 3\n",
		"# TYPE sentinel_tunnel_sessions_cleartext gauge\n",
		"sentinel_tunnel_sessions_cleartext 1\n",
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
	_, _, err = registry.Register(&TunnelHandshake{SpotID: "b", Ports: []int{22}}, nil, TunnelTransportCleartext)
	require.NoError(t, err)
	registry.noteCleartextRefused()
	registry.noteCleartextRefused()

	m := NewManager(Config{}, &fakeRecoveryProvider{})
	m.SetTunnelRegistry(registry)

	rec := httptest.NewRecorder()
	m.MetricsHandler()(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	assert.Contains(t, body, "sentinel_tunnel_sessions_tls 1\n")
	assert.Contains(t, body, "sentinel_tunnel_sessions_cleartext 1\n")
	assert.Contains(t, body, "sentinel_tunnel_cleartext_refused_total 2\n")

	rec = httptest.NewRecorder()
	StatusHandler(m)(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	page := rec.Body.String()
	assert.Contains(t, page, "tunnel_sessions_tls")
	assert.Contains(t, page, "tunnel_sessions_cleartext")
	assert.True(t, strings.Contains(page, ">1<"), "session counts must be rendered")
}
