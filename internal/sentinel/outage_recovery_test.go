package sentinel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Advance the registration clock past its TTL, then rebind the backend's
// exact address with a new TLS identity. This models expiry deterministically;
// the separate live harness measures real outage durations and SSH recovery.
func TestBackendOutage_SameIPReregisterWithRotatedTLS(t *testing.T) {
	const hostname = "backend.example"
	backendAddr := "127.0.0.1:0"
	roots := x509.NewCertPool()
	startBackend := func(marker string) *http.Server {
		pair := testCertPairFrom(t, hostname, marker)
		cert, err := tls.X509KeyPair([]byte(pair.CertPEM), []byte(pair.KeyPEM))
		require.NoError(t, err)
		require.True(t, roots.AppendCertsFromPEM([]byte(pair.CertPEM)))
		ln, err := net.Listen("tcp", backendAddr)
		require.NoError(t, err)
		backendAddr = ln.Addr().String()
		srv := &http.Server{
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, marker)
			}),
		}
		go func() { _ = srv.ServeTLS(ln, "", "") }()
		t.Cleanup(func() { _ = srv.Close() })
		return srv
	}
	before := startBackend("before")
	m := routingSelfCheckManager(t, "127.0.0.1:1")
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	m.primaries.now = func() time.Time { return time.Unix(0, clock.Load()) }
	host, port, err := net.SplitHostPort(backendAddr)
	require.NoError(t, err)
	p := Primary{Pool: "test", Hostname: hostname, IP: host, Port: mustAtoi(t, port)}
	m.primaries.Register(p)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(m.config.HTTPSPort)))
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	check := func(marker string) {
		resp, err := client.Get("https://" + hostname)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, marker, string(body))
		require.Equal(t, []string{marker}, resp.TLS.PeerCertificates[0].Subject.Organization)
	}
	check("before")
	require.NoError(t, before.Close())
	clock.Add(int64(8 * time.Hour))
	require.Nil(t, m.primaries.LookupByHostname(hostname))
	exits := 0
	m.exitFn = func() { exits++ }
	for range m.config.SelfCheckFailureThreshold + 1 {
		failures, triggered := m.selfCheckOnce(0)
		require.Zero(t, failures)
		require.False(t, triggered)
	}
	startBackend("after")
	m.primaries.Register(p)
	check("after")
	require.Zero(t, exits)
}
