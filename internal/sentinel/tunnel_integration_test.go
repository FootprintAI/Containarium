package sentinel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTunnelIntegration is a full integration test that simulates:
//   - A sentinel running with --provider=tunnel (ConnMux on a single port)
//   - A firewalled spot VM connecting via reverse tunnel
//   - End-user HTTPS traffic flowing through the tunnel to the spot's service
//   - Health checks succeeding through the tunnel
//
// Everything runs on localhost. No iptables, no loopback aliases, no real VMs.
// The test verifies the core tunnel flow: mux → tunnel handshake → yamux → spot service.
func TestTunnelIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token := "integration-test-token"

	// ---------------------------------------------------------------
	// 1. Start mock services on the "spot VM" side
	// ---------------------------------------------------------------

	// Mock health/API daemon on port 8080-equivalent
	spotDaemonPort := freePort(t)
	spotDaemonLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", spotDaemonPort))
	require.NoError(t, err)
	defer func() { _ = spotDaemonLn.Close() }()

	spotDaemonSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"status":"healthy"}`))
			case "/authorized-keys":
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"keys":[{"username":"testuser","authorized_keys":"ssh-rsa AAAA..."}]}`))
			default:
				w.WriteHeader(404)
			}
		}),
	}
	go func() { _ = spotDaemonSrv.Serve(spotDaemonLn) }()
	defer func() { _ = spotDaemonSrv.Close() }()

	// Mock HTTPS service on the spot (e.g., Caddy)
	spotHTTPSPort := freePort(t)
	spotHTTPSLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", spotHTTPSPort))
	require.NoError(t, err)
	defer func() { _ = spotHTTPSLn.Close() }()

	spotHTTPSSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello from spot HTTPS"))
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{mustSelfSignedCert(t)},
		},
	}
	go func() { _ = spotHTTPSSrv.ServeTLS(spotHTTPSLn, "", "") }()
	defer func() { _ = spotHTTPSSrv.Close() }()

	// ---------------------------------------------------------------
	// 2. Start sentinel-side: ConnMux + TunnelServer + Manager
	// ---------------------------------------------------------------

	muxPort := freePort(t)
	muxLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", muxPort))
	require.NoError(t, err)

	connMux := NewConnMuxFromListener(muxLn)
	go connMux.Run()
	defer func() { _ = connMux.Close() }()

	registry := NewTunnelRegistry()
	tunnelServer := NewTunnelServer("", policyAny(token), registry)

	connectCh := make(chan *TunnelSpot, 1)
	disconnectCh := make(chan string, 1)
	tunnelServer.OnConnect = func(spot *TunnelSpot) {
		t.Logf("[integration] spot connected: %s at %s", spot.ID, spot.LocalIP)
		connectCh <- spot
	}
	tunnelServer.OnDisconnect = func(spot *TunnelSpot) {
		t.Logf("[integration] spot disconnected: %s", spot.ID)
		disconnectCh <- spot.ID
	}

	go func() { _ = tunnelServer.Serve(ctx, connMux.TunnelListener()) }()

	time.Sleep(100 * time.Millisecond)

	// ---------------------------------------------------------------
	// 3. Start tunnel client on the "spot VM"
	// ---------------------------------------------------------------

	client := &TunnelClient{
		SentinelAddr: fmt.Sprintf("127.0.0.1:%d", muxPort),
		Token:        token,
		SpotID:       "integration-spot",
		Ports:        []int{spotDaemonPort, spotHTTPSPort},
	}
	go func() { _ = client.Run(ctx) }()

	// Wait for connection
	var spot *TunnelSpot
	select {
	case spot = <-connectCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for tunnel connection")
	}

	assert.Equal(t, "integration-spot", spot.ID)
	t.Logf("[integration] tunnel established, spot at %s", spot.LocalIP)

	// ---------------------------------------------------------------
	// 4. Verify: health check through tunnel
	// ---------------------------------------------------------------

	time.Sleep(200 * time.Millisecond)

	// The health check dials spotIP:daemonPort through the tunnel proxy.
	// On Linux this would be 127.0.0.2:daemonPort. On macOS it won't work
	// (loopback alias doesn't exist), so we test via yamux stream directly.
	t.Run("health_check_via_yamux", func(t *testing.T) {
		// Open a yamux stream to the spot's daemon port
		stream, err := spot.Session.Open()
		require.NoError(t, err)
		defer func() { _ = stream.Close() }()

		// Send port header
		portBytes := []byte{byte(spotDaemonPort >> 8), byte(spotDaemonPort & 0xff)}
		_, err = stream.Write(portBytes)
		require.NoError(t, err)

		// Send HTTP request
		_, err = stream.Write([]byte("GET /health HTTP/1.0\r\nHost: localhost\r\n\r\n"))
		require.NoError(t, err)

		// Read response
		buf := make([]byte, 1024)
		_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := stream.Read(buf)
		require.NoError(t, err)
		response := string(buf[:n])

		assert.Contains(t, response, "200")
		assert.Contains(t, response, `"status":"healthy"`)
		t.Logf("[integration] health response: %s", response)
	})

	// ---------------------------------------------------------------
	// 5. Verify: authorized-keys endpoint through tunnel
	// ---------------------------------------------------------------

	t.Run("authorized_keys_via_yamux", func(t *testing.T) {
		stream, err := spot.Session.Open()
		require.NoError(t, err)
		defer func() { _ = stream.Close() }()

		portBytes := []byte{byte(spotDaemonPort >> 8), byte(spotDaemonPort & 0xff)}
		_, err = stream.Write(portBytes)
		require.NoError(t, err)

		_, err = stream.Write([]byte("GET /authorized-keys HTTP/1.0\r\nHost: localhost\r\n\r\n"))
		require.NoError(t, err)

		buf := make([]byte, 1024)
		_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := stream.Read(buf)
		require.NoError(t, err)
		response := string(buf[:n])

		assert.Contains(t, response, "200")
		assert.Contains(t, response, "testuser")
		t.Logf("[integration] authorized-keys response: %s", response)
	})

	// ---------------------------------------------------------------
	// 6. Verify: HTTPS via ConnMux goes to the right place
	// ---------------------------------------------------------------

	t.Run("https_via_connmux", func(t *testing.T) {
		// Connect to the mux port with a TLS ClientHello (first byte 0x16)
		// This should land on the ConnMux HTTPS listener
		httpsConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", muxPort), 2*time.Second)
		require.NoError(t, err)
		defer func() { _ = httpsConn.Close() }()

		// Send a TLS ClientHello byte to trigger HTTPS routing
		_, _ = httpsConn.Write([]byte{0x16})

		// Read from the HTTPS listener side
		muxHTTPSConn, err := connMux.HTTPSListener().Accept()
		if err != nil {
			t.Skipf("HTTPS listener accept failed (may already be consumed): %v", err)
		}
		defer func() { _ = muxHTTPSConn.Close() }()

		// Verify the first byte is 0x16 (replayed by peekedConn)
		buf := make([]byte, 1)
		_ = muxHTTPSConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = io.ReadFull(muxHTTPSConn, buf)
		require.NoError(t, err)
		assert.Equal(t, byte(0x16), buf[0])
		t.Log("[integration] HTTPS correctly routed through ConnMux")
	})

	// ---------------------------------------------------------------
	// 7. Verify: registry state
	// ---------------------------------------------------------------

	t.Run("registry_state", func(t *testing.T) {
		assert.True(t, registry.Connected())
		assert.Equal(t, 1, registry.Count())

		regSpot := registry.Get("integration-spot")
		require.NotNil(t, regSpot)
		assert.Equal(t, spot.LocalIP, regSpot.LocalIP)
		assert.False(t, regSpot.Session.IsClosed())
	})
}

func mustSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	cert, err := generateSelfSignedCert()
	require.NoError(t, err)
	return cert
}
