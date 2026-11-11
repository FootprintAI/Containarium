package sentinel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeConsoleRouterTestCert writes a self-signed 127.0.0.1 certificate and
// key into dir and returns their paths. The cert doubles as its own CA.
func writeConsoleRouterTestCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "console-router-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}

// TestConsoleRouterTLS: with a cert and key configured the router accepts
// only TLS (#3523). The wrong-token request never reaches the tunnel
// registry, so the TLS-vs-plaintext behaviour is observable without a tunnel.
func TestConsoleRouterTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	certFile, keyFile := writeConsoleRouterTestCert(t, t.TempDir())
	serverCfg, err := ConsoleRouterServerTLSConfig(certFile, keyFile)
	require.NoError(t, err)
	clientCfg, err := ConsoleRouterClientTLSConfig(certFile)
	require.NoError(t, err)

	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	router := NewConsoleRouter(addr, NewConsoleRouterPolicy("tok"), NewTunnelRegistry())
	router.SetTLSConfig(serverCfg)
	go func() { _ = router.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)

	hs := ConsoleRouterHandshake{Token: "wrong", SpotID: "s", Port: 1}

	t.Run("TLS client gets a router response", func(t *testing.T) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, clientCfg)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		require.NoError(t, json.NewEncoder(conn).Encode(hs))
		var resp ConsoleRouterResponse
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		require.NoError(t, json.NewDecoder(conn).Decode(&resp))
		assert.False(t, resp.OK)
		assert.Equal(t, "unauthorized", resp.Error)
	})

	t.Run("plaintext client is refused", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		require.NoError(t, json.NewEncoder(conn).Encode(hs))
		var resp ConsoleRouterResponse
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_ = json.NewDecoder(conn).Decode(&resp)
		assert.Empty(t, resp.Error, "no router response may be served in plaintext on a TLS router")
	})

	t.Run("client without the CA is refused", func(t *testing.T) {
		_, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{MinVersion: tls.VersionTLS12})
		assert.Error(t, err)
	})
}

func TestConsoleRouterTLSConfig_BadInput(t *testing.T) {
	_, err := ConsoleRouterServerTLSConfig("/nonexistent/cert.pem", "/nonexistent/key.pem")
	assert.Error(t, err)
	_, err = ConsoleRouterClientTLSConfig("/nonexistent/ca.pem")
	assert.Error(t, err)
	bad := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(bad, []byte("not pem"), 0o600))
	_, err = ConsoleRouterClientTLSConfig(bad)
	assert.Error(t, err)
}

// TestConsoleRouterWarnsWithoutTLS: without a cert the router stays plaintext
// but says so at startup (#3523).
func TestConsoleRouterWarnsWithoutTLS(t *testing.T) {
	var buf syncBuffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	router := NewConsoleRouter(fmt.Sprintf("127.0.0.1:%d", freePort(t)), NewConsoleRouterPolicy("tok"), NewTunnelRegistry())
	go func() { _ = router.Run(ctx) }()
	require.Eventually(t, func() bool { return strings.Contains(buf.String(), "WARNING") }, 3*time.Second, 20*time.Millisecond)
	assert.Contains(t, buf.String(), "plaintext")
}
