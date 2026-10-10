package sentinel

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTunnelHandshakeValidation(t *testing.T) {
	tests := []struct {
		name    string
		hs      *TunnelHandshake
		token   string
		wantErr bool
	}{
		{
			name:    "valid",
			hs:      &TunnelHandshake{Token: "secret", SpotID: "spot-1", Ports: []int{80, 443}},
			token:   "secret",
			wantErr: false,
		},
		{
			name:    "wrong token",
			hs:      &TunnelHandshake{Token: "wrong", SpotID: "spot-1", Ports: []int{80}},
			token:   "secret",
			wantErr: true,
		},
		{
			name:    "missing spot id",
			hs:      &TunnelHandshake{Token: "secret", SpotID: "", Ports: []int{80}},
			token:   "secret",
			wantErr: true,
		},
		{
			name:    "no ports",
			hs:      &TunnelHandshake{Token: "secret", SpotID: "spot-1", Ports: nil},
			token:   "secret",
			wantErr: true,
		},
		{
			name:    "primary handshake valid",
			hs:      &TunnelHandshake{Token: "secret", SpotID: "spot-1", Ports: []int{443}, Pool: "lab", PublicHostname: "lab.example", PublicPort: 443},
			token:   "secret",
			wantErr: false,
		},
		{
			name:    "primary handshake without public_port",
			hs:      &TunnelHandshake{Token: "secret", SpotID: "spot-1", Ports: []int{443}, Pool: "lab", PublicHostname: "lab.example"},
			token:   "secret",
			wantErr: true,
		},
		{
			name:    "primary handshake without pool",
			hs:      &TunnelHandshake{Token: "secret", SpotID: "spot-1", Ports: []int{443}, PublicHostname: "lab.example", PublicPort: 443},
			token:   "secret",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := NewTokenPolicy()
			policy.Allow(tt.token, PoolAny)
			err := validateHandshake(tt.hs, policy)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTunnelRegistryAllocate(t *testing.T) {
	registry := NewTunnelRegistry()

	assert.False(t, registry.Connected())
	assert.Equal(t, 0, registry.Count())
	assert.Nil(t, registry.GetFirst())
}

// TestTunnelEndToEnd tests the full tunnel flow: server + client + port forwarding.
// On Linux (with loopback aliases), it verifies full data flow through the tunnel.
// On non-Linux, it verifies handshake, registration, and session establishment.
func TestTunnelEndToEnd(t *testing.T) {
	withRecordedAliases(t)

	if testing.Short() {
		t.Skip("skipping end-to-end tunnel test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token := "test-token"
	echoPort := freePort(t)
	tunnelPort := freePort(t)

	// 1. Start a mock echo service on the "spot" side
	echoLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	require.NoError(t, err)
	defer func() { _ = echoLn.Close() }()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c) // echo
			}(conn)
		}
	}()

	// 2. Start tunnel server
	registry := NewTunnelRegistry()
	server := NewTunnelServer(fmt.Sprintf("127.0.0.1:%d", tunnelPort), policyAny(token), registry, 0)
	id := newTestTunnelIdentity(t)
	server.SetTunnelIdentity(id)

	connectCh := make(chan *TunnelSpot, 1)
	server.OnConnect = func(spot *TunnelSpot) {
		connectCh <- spot
	}

	go func() { _ = server.Run(ctx) }()
	waitForListener(t, fmt.Sprintf("127.0.0.1:%d", tunnelPort))

	// 3. Start tunnel client, pinning the server's tunnel identity
	client := &TunnelClient{
		SentinelAddr: fmt.Sprintf("127.0.0.1:%d", tunnelPort),
		SentinelPins: []TunnelPin{id.Pin()},
		Token:        token,
		SpotID:       "test-spot",
		Ports:        []int{echoPort},
	}
	go func() { _ = client.Run(ctx) }()

	// 4. Wait for connection
	var spot *TunnelSpot
	select {
	case spot = <-connectCh:
		t.Logf("spot connected: %s at %s", spot.ID, spot.LocalIP)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for tunnel connection")
	}

	assert.Equal(t, "test-spot", spot.ID)
	assert.NotEmpty(t, spot.LocalIP)
	assert.True(t, registry.Connected())
	assert.Equal(t, 1, registry.Count())

	// 5. Try to connect through the tunnel proxy.
	// On Linux, the proxy binds to 127.0.0.2:echoPort (loopback alias).
	// On macOS, the alias doesn't exist, so the proxy either fails to bind
	// or falls back to 127.0.0.1 (which may conflict with the echo service).
	// The proxy listener is bound after OnConnect fires, so poll for it
	// rather than sleeping a fixed amount (flaky on a loaded runner).
	proxyAddr := net.JoinHostPort(spot.LocalIP, fmt.Sprintf("%d", echoPort))
	conn, err := dialRetry(proxyAddr, 2*time.Second)
	if err != nil {
		t.Logf("proxy not reachable at %s (expected on non-Linux): %v", proxyAddr, err)
		t.Log("tunnel handshake, yamux session, and registration verified successfully")
		return
	}
	defer func() { _ = conn.Close() }()

	// Full data flow test (Linux with working loopback alias)
	testData := "hello through the tunnel!"
	_, err = conn.Write([]byte(testData))
	require.NoError(t, err)

	buf := make([]byte, len(testData))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)

	assert.Equal(t, testData, string(buf))
	t.Logf("full echo through tunnel verified: %q", string(buf))
}

// TestTunnelWrongToken verifies that a client with the wrong token is rejected.
func TestTunnelWrongToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tunnelPort := freePort(t)
	registry := NewTunnelRegistry()
	server := NewTunnelServer(fmt.Sprintf("127.0.0.1:%d", tunnelPort), policyAny("correct-token"), registry, 0)

	go func() { _ = server.Run(ctx) }()
	waitForListener(t, fmt.Sprintf("127.0.0.1:%d", tunnelPort))

	// Connect with wrong token
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tunnelPort), 3*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	hs := &TunnelHandshake{Token: "wrong-token", SpotID: "bad-spot", Ports: []int{80}}
	err = writeHandshake(conn, hs)
	require.NoError(t, err)

	resp, err := readHandshakeResponse(conn)
	require.NoError(t, err)
	assert.False(t, resp.OK)
	assert.Contains(t, resp.Error, "invalid token")

	// Should not be registered
	assert.False(t, registry.Connected())
}

// TestConnMuxRouting verifies that the ConnMux correctly routes connections
// based on the first byte: '{' → tunnel listener, 0x16 → HTTPS listener.
func TestConnMuxRouting(t *testing.T) {
	muxPort := freePort(t)
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", muxPort))
	require.NoError(t, err)

	mux := NewConnMuxFromListener(ln)
	go mux.Run()
	defer func() { _ = mux.Close() }()
	waitForListener(t, fmt.Sprintf("127.0.0.1:%d", muxPort))

	// Test 1: Send a '{' byte → should appear on TunnelListener
	tunnelDone := make(chan string, 1)
	go func() {
		conn, err := mux.TunnelListener().Accept()
		if err != nil {
			tunnelDone <- "error: " + err.Error()
			return
		}
		buf := make([]byte, 16)
		n, _ := conn.Read(buf)
		_ = conn.Close()
		tunnelDone <- string(buf[:n])
	}()

	conn1, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", muxPort))
	require.NoError(t, err)
	_, _ = conn1.Write([]byte(`{"token":"x"}`))
	_ = conn1.Close()

	select {
	case data := <-tunnelDone:
		// The first byte '{' was peeked, so the full JSON should be readable
		assert.True(t, len(data) > 0 && data[0] == '{', "tunnel should receive JSON starting with '{'")
		t.Logf("tunnel listener received: %s", data)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for tunnel listener")
	}

	// Test 2: Send a TLS ClientHello (first byte 0x16) → should appear on HTTPSListener
	httpsDone := make(chan byte, 1)
	go func() {
		conn, err := mux.HTTPSListener().Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_ = conn.Close()
		httpsDone <- buf[0]
	}()

	conn2, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", muxPort))
	require.NoError(t, err)
	_, _ = conn2.Write([]byte{0x16, 0x03, 0x01}) // TLS record header
	_ = conn2.Close()

	select {
	case firstByte := <-httpsDone:
		assert.Equal(t, byte(0x16), firstByte, "HTTPS listener should receive TLS byte")
		t.Logf("HTTPS listener received first byte: 0x%02x", firstByte)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for HTTPS listener")
	}
}

// TestConnMuxWithTunnelClient verifies that a tunnel client can connect through
// a ConnMux on the same port as HTTPS.
func TestConnMuxWithTunnelClient(t *testing.T) {
	withRecordedAliases(t)

	if testing.Short() {
		t.Skip("skipping ConnMux+tunnel test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	token := "mux-test-token"
	muxPort := freePort(t)
	echoPort := freePort(t)

	// Start echo service
	echoLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	require.NoError(t, err)
	defer func() { _ = echoLn.Close() }()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// Start ConnMux
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", muxPort))
	require.NoError(t, err)
	mux := NewConnMuxFromListener(ln)
	go mux.Run()
	defer func() { _ = mux.Close() }()

	// Start tunnel server on the mux's tunnel listener
	registry := NewTunnelRegistry()
	tunnelServer := NewTunnelServer("", policyAny(token), registry, 0)
	id := newTestTunnelIdentity(t)
	tunnelServer.SetTunnelIdentity(id)
	connectCh := make(chan *TunnelSpot, 1)
	tunnelServer.OnConnect = func(spot *TunnelSpot) {
		connectCh <- spot
	}
	go func() { _ = tunnelServer.Serve(ctx, mux.TunnelListener()) }()
	waitForListener(t, fmt.Sprintf("127.0.0.1:%d", muxPort))

	// Start tunnel client pointing at the mux port (same as HTTPS); the
	// mux routes its TLS session by ALPN to the tunnel server.
	client := &TunnelClient{
		SentinelAddr: fmt.Sprintf("127.0.0.1:%d", muxPort),
		SentinelPins: []TunnelPin{id.Pin()},
		Token:        token,
		SpotID:       "mux-spot",
		Ports:        []int{echoPort},
	}
	go func() { _ = client.Run(ctx) }()

	// Wait for connection
	select {
	case spot := <-connectCh:
		assert.Equal(t, "mux-spot", spot.ID)
		t.Logf("tunnel client connected through ConnMux: %s at %s", spot.ID, spot.LocalIP)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for tunnel connection through ConnMux")
	}

	assert.True(t, registry.Connected())
}

// waitForListener blocks until addr accepts a TCP connection, failing the
// test after a generous deadline. Tests used to `time.Sleep(100ms)` after
// starting a server goroutine and then dial; on a loaded CI runner the
// listener was not always bound yet and the dial got "connection refused".
// A readiness poll is both faster on an idle machine and correct on a busy
// one.
func waitForListener(t *testing.T, addr string) {
	t.Helper()
	if _, err := dialRetry(addr, 5*time.Second); err != nil {
		t.Fatalf("listener %s never came up: %v", addr, err)
	}
}

// dialRetry dials addr until it succeeds or timeout elapses, returning the
// open connection or the last dial error.
func dialRetry(addr string, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return nil, lastErr
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// policyAny returns a TokenPolicy authorizing the given token for any pool.
// Test helper for the legacy single-token path.
func policyAny(token string) *TokenPolicy {
	p := NewTokenPolicy()
	p.Allow(token, PoolAny)
	return p
}
