package sentinel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestTunnelIdentity generates a throwaway sentinel tunnel identity.
func newTestTunnelIdentity(t *testing.T) *TunnelIdentity {
	t.Helper()
	id, err := GenerateTunnelIdentity()
	require.NoError(t, err)
	return id
}

// startTLSTunnelFront terminates the tunnel TLS transport with id and
// forwards the decrypted bytes to backendAddr (a plain TunnelServer or a
// ConnMux). It lets tests drive an unchanged TunnelServer from a TLS client.
// Returns the address clients dial.
func startTLSTunnelFront(t *testing.T, id *TunnelIdentity, backendAddr string) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tunnelTLSServerConfig(id))
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(front net.Conn) {
				defer func() { _ = front.Close() }()
				if err := front.(*tls.Conn).Handshake(); err != nil {
					return
				}
				back, err := net.DialTimeout("tcp", backendAddr, 5*time.Second)
				if err != nil {
					return
				}
				defer func() { _ = back.Close() }()
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(back, front); done <- struct{}{} }()
				go func() { _, _ = io.Copy(front, back); done <- struct{}{} }()
				<-done
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// countingListener counts the application bytes its accepted connections
// deliver to the reader (for a TLS listener: decrypted bytes only).
type countingListener struct {
	net.Listener
	n *atomic.Int64
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return countingConn{Conn: c, n: l.n}, nil
}

type countingConn struct {
	net.Conn
	n *atomic.Int64
}

func (c countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// startEchoService runs a TCP echo server on 127.0.0.1 and returns its port.
func startEchoService(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestTunnelTLSEndToEnd: a client holding the sentinel's pin registers over
// TLS and a stream round-trips through the tunnel.
func TestTunnelTLSEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stubLoopbackAliases(t)
	const token = "tls-token"
	echoPort := startEchoService(t)
	id := newTestTunnelIdentity(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	registry := NewTunnelRegistry()
	server := NewTunnelServer("", policyAny(token), registry, 0)
	server.SetTunnelIdentity(id)
	connectCh := make(chan *TunnelSpot, 1)
	server.OnConnect = func(spot *TunnelSpot) {
		select {
		case connectCh <- spot:
		default:
		}
	}
	go func() { _ = server.Serve(ctx, ln) }()

	client := &TunnelClient{
		SentinelAddr: ln.Addr().String(),
		SentinelPins: []TunnelPin{id.Pin()},
		Token:        token,
		SpotID:       "tls-spot",
		Ports:        []int{echoPort},
	}
	go func() { _ = client.Run(ctx) }()

	select {
	case spot := <-connectCh:
		assert.Equal(t, "tls-spot", spot.ID)
		assert.Equal(t, TunnelTransportTLS, spot.Transport)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for TLS tunnel registration")
	}
	stats := registry.SessionStats()
	assert.Equal(t, 1, stats.TLS)
	assert.Zero(t, stats.Cleartext)

	stream, err := registry.DialTunnel("tls-spot", echoPort)
	require.NoError(t, err)
	defer func() { _ = stream.Close() }()
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	msg := []byte("hello over tls")
	_, err = stream.Write(msg)
	require.NoError(t, err)
	got := make([]byte, len(msg))
	_, err = io.ReadFull(stream, got)
	require.NoError(t, err)
	assert.Equal(t, msg, got)
}

// TestTunnelPinMismatchAbortsBeforeHandshake: the sentinel presents an
// identity the client does not pin. The client aborts inside the TLS
// handshake, so the server side receives zero application bytes and
// nothing registers.
//
// The first variant terminates TLS in front of the server so the bytes the
// server reads are exactly the decrypted application bytes, which must be
// zero. The second runs the server's own TLS listener path and checks the
// outcome the sentinel observes: no registration, no callback, no refusal
// counted.
func TestTunnelPinMismatchAbortsBeforeHandshake(t *testing.T) {
	serverID := newTestTunnelIdentity(t)
	pinnedID := newTestTunnelIdentity(t)

	t.Run("zero application bytes reach the server", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		var appBytes atomic.Int64
		registry := NewTunnelRegistry()
		server := NewTunnelServer("", policyAny("tok"), registry, 0)
		tlsLn := countingListener{Listener: tls.NewListener(ln, tunnelTLSServerConfig(serverID)), n: &appBytes}
		go func() { _ = server.Serve(ctx, tlsLn) }()

		client := &TunnelClient{
			SentinelAddr: ln.Addr().String(),
			SentinelPins: []TunnelPin{pinnedID.Pin()},
			Token:        "tok",
			SpotID:       "mismatch-spot",
			Ports:        []int{22},
		}
		err = client.connectAndServe(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "pin")

		// Give the server goroutine time to observe the failed handshake.
		time.Sleep(200 * time.Millisecond)
		assert.Zero(t, appBytes.Load(), "server must receive no application bytes")
		assert.Zero(t, registry.Count())
	})

	t.Run("server-side TLS listener registers nothing", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		registry := NewTunnelRegistry()
		server := NewTunnelServer("", policyAny("tok"), registry, 0)
		server.SetTunnelIdentity(serverID)
		var connects atomic.Int32
		server.OnConnect = func(*TunnelSpot) { connects.Add(1) }
		go func() { _ = server.Serve(ctx, ln) }()

		client := &TunnelClient{
			SentinelAddr: ln.Addr().String(),
			SentinelPins: []TunnelPin{pinnedID.Pin()},
			Token:        "tok",
			SpotID:       "mismatch-spot",
			Ports:        []int{22},
		}
		err = client.connectAndServe(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "pin")

		time.Sleep(200 * time.Millisecond)
		assert.Zero(t, registry.Count())
		assert.Zero(t, connects.Load())
		stats := registry.SessionStats()
		assert.Zero(t, stats.TLS)
		assert.Zero(t, stats.Cleartext)
		assert.Zero(t, stats.CleartextRefused, "a failed TLS handshake is not a cleartext refusal")
	})
}

// TestNewClientNoCleartextFallback: against a peer that does not speak TLS
// (here: one that answers like a cleartext tunnel endpoint) the client
// returns an error and never sends the JSON handshake. Every byte it writes
// belongs to the TLS ClientHello: the stream starts with the TLS handshake
// record type (0x16), never with '{', and neither the token nor any
// handshake field appears on the wire.
func TestNewClientNoCleartextFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const token = "never-on-the-wire"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	var (
		mu       sync.Mutex
		captured [][]byte
	)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = c.Write([]byte(`{"ok":true,"assigned_ip":"127.0.0.2"}` + "\n"))
				var buf bytes.Buffer
				_, _ = io.Copy(&buf, c)
				mu.Lock()
				captured = append(captured, buf.Bytes())
				mu.Unlock()
			}(c)
		}
	}()

	client := &TunnelClient{
		SentinelAddr: ln.Addr().String(),
		SentinelPins: []TunnelPin{newTestTunnelIdentity(t).Pin()},
		Token:        token,
		SpotID:       "fallback-spot",
		Ports:        []int{22},
	}
	err = client.connectAndServe(ctx)
	require.Error(t, err)

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(captured) == 1
	}, 5*time.Second, 20*time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	wire := captured[0]
	require.NotEmpty(t, wire)
	assert.Equal(t, byte(0x16), wire[0], "first byte must be a TLS handshake record, not '{'")
	assert.False(t, bytes.Contains(wire, []byte(token)), "token must not appear on the wire")
	assert.False(t, bytes.Contains(wire, []byte(`"spot_id"`)), "JSON handshake must not be sent")
}

// TestTunnelClientRequiresPins: a client without any pin refuses to dial.
func TestTunnelClientRequiresPins(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	var accepted atomic.Bool
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted.Store(true)
			_ = c.Close()
		}
	}()

	client := &TunnelClient{SentinelAddr: ln.Addr().String(), Token: "t", SpotID: "s", Ports: []int{22}}
	err = client.connectAndServe(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoSentinelPins), "got %v", err)
	time.Sleep(50 * time.Millisecond)
	assert.False(t, accepted.Load(), "client must not connect without a pin")
}

// TestTunnelClientTLSConfig pins the transport parameters: TLS 1.3 only,
// the tunnel ALPN protocol, SNI taken from the sentinel address host, and
// peer verification by pin.
func TestTunnelClientTLSConfig(t *testing.T) {
	id := newTestTunnelIdentity(t)
	other := newTestTunnelIdentity(t)
	tests := []struct {
		addr    string
		wantSNI string
	}{
		{"sentinel.example.com:443", "sentinel.example.com"},
		{"[2001:db8::1]:9443", "2001:db8::1"},
		{"192.0.2.10:443", "192.0.2.10"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			tc := &TunnelClient{SentinelAddr: tt.addr, SentinelPins: []TunnelPin{id.Pin()}}
			cfg, err := tc.tlsConfig()
			require.NoError(t, err)
			assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
			assert.Equal(t, []string{TunnelALPN}, cfg.NextProtos)
			assert.Equal(t, tt.wantSNI, cfg.ServerName)
			require.NotNil(t, cfg.VerifyPeerCertificate)
			assert.NoError(t, cfg.VerifyPeerCertificate([][]byte{id.TLSCertificate().Certificate[0]}, nil))
			assert.Error(t, cfg.VerifyPeerCertificate([][]byte{other.TLSCertificate().Certificate[0]}, nil))
		})
	}
	_, err := (&TunnelClient{SentinelAddr: "no-port", SentinelPins: []TunnelPin{id.Pin()}}).tlsConfig()
	assert.Error(t, err)
}
