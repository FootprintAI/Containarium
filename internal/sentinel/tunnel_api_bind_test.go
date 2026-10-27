package sentinel

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// apiPortOrSkip skips when the backend API port (8080) cannot be bound on
// loopback. startProxies binds that port as-is and only adds the per-backend
// API listener after it succeeds, so a busy 8080 would leave nothing to check.
func apiPortOrSkip(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Skipf("port 8080 is in use on this machine: %v", err)
	}
	require.NoError(t, l.Close())
}

// listenerAddrs returns the bound addresses of a spot's proxy listeners.
func listenerAddrs(t *testing.T, ts *TunnelServer, spotID string) []*net.TCPAddr {
	t.Helper()
	ts.mu.Lock()
	defer ts.mu.Unlock()
	var out []*net.TCPAddr
	for _, ln := range ts.proxies[spotID].listeners {
		out = append(out, ln.Addr().(*net.TCPAddr))
	}
	return out
}

// nonLoopbackIPv4 returns a local IPv4 address that is not loopback, or nil.
func nonLoopbackIPv4(t *testing.T) net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	require.NoError(t, err)
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
			return ipn.IP
		}
	}
	return nil
}

func TestNewTunnelServer_DefaultAPIBindAddrIsLoopback(t *testing.T) {
	ts := NewTunnelServer("", NewTokenPolicy(), NewTunnelRegistry(), 0)
	require.Equal(t, "127.0.0.1", ts.APIBindAddr)
	require.Equal(t, DefaultTunnelAPIBindAddr, ts.APIBindAddr)
}

func TestStartProxies_APIListenerBoundToLoopbackByDefault(t *testing.T) {
	stubLoopbackAliases(t)
	apiPortOrSkip(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session, closeSession := newSessionPair(t)
	defer closeSession()

	ts := NewTunnelServer("", NewTokenPolicy(), NewTunnelRegistry(), 0)
	closeProxiesOnCleanup(t, ts)

	apiPort := freeLoopbackPort(t)
	ts.startProxies(ctx, "spot-1", 1, "127.0.0.1", apiPort, []int{8080}, session)

	addrs := listenerAddrs(t, ts, "spot-1")
	var found bool
	for _, a := range addrs {
		require.Truef(t, a.IP.IsLoopback(), "listener %s is not bound to loopback", a)
		if a.Port == apiPort {
			found = true
		}
	}
	require.Truef(t, found, "no listener on the per-backend API port %d; got %v", apiPort, addrs)

	// The API port accepts on loopback...
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(apiPort)), time.Second)
	require.NoError(t, err)
	_ = c.Close()

	// ...and refuses on any non-loopback local address.
	if ip := nonLoopbackIPv4(t); ip != nil {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(apiPort)), time.Second)
		if err == nil {
			_ = c.Close()
		}
		require.Errorf(t, err, "API port %d accepted a connection on non-loopback address %s", apiPort, ip)
	}
}

func TestStartProxies_APIListenerHonoursAPIBindAddr(t *testing.T) {
	stubLoopbackAliases(t)
	apiPortOrSkip(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session, closeSession := newSessionPair(t)
	defer closeSession()

	ts := NewTunnelServer("", NewTokenPolicy(), NewTunnelRegistry(), 0)
	ts.APIBindAddr = "0.0.0.0"
	closeProxiesOnCleanup(t, ts)

	apiPort := freeLoopbackPort(t)
	ts.startProxies(ctx, "spot-1", 1, "127.0.0.1", apiPort, []int{8080}, session)

	var api *net.TCPAddr
	for _, a := range listenerAddrs(t, ts, "spot-1") {
		if a.Port == apiPort {
			api = a
		}
	}
	require.NotNil(t, api, "no listener on the per-backend API port")
	require.Truef(t, api.IP.IsUnspecified(), "API listener bound to %s, want the configured 0.0.0.0", api.IP)
}
