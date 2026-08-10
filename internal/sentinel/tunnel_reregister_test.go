package sentinel

// Regression tests for #769: after a backend reboot / spot preemption the
// backend reconnects under the SAME spot id, and the sentinel used to tear the
// FRESH registration down — leaving a live tunnel that nothing routed over
// until an operator ran `systemctl restart` on the sentinel by hand.
//
// The mechanism: TunnelRegistry.Register closes the previous yamux session in
// order to replace the entry. That close wakes the goroutine monitoring the
// OLD session, which then runs its ordinary disconnect cleanup — closing proxy
// listeners, dropping the loopback alias, and (via OnDisconnect) stripping the
// backend's users out of the sshpiper config. All of it aimed at the
// registration that had just replaced it.
//
// These tests pin the generation guard that stops it.

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/require"
)

// stubLoopbackAliases replaces the `ip addr` calls for the duration of a test.
// Registration bookkeeping does not need CAP_NET_ADMIN to be worth testing.
func stubLoopbackAliases(t *testing.T) {
	t.Helper()
	origAdd, origRemove := addLoopbackAliasFn.Load(), removeLoopbackAliasFn.Load()
	add := func(string) error { return nil }
	remove := func(string) {}
	addLoopbackAliasFn.Store(&add)
	removeLoopbackAliasFn.Store(&remove)
	t.Cleanup(func() {
		addLoopbackAliasFn.Store(origAdd)
		removeLoopbackAliasFn.Store(origRemove)
	})
}

// newSessionPair returns a live yamux session pair over an in-memory pipe.
// The "sentinel side" is the one the registry stores.
func newSessionPair(t *testing.T) (sentinelSide *yamux.Session, cleanup func()) {
	t.Helper()
	backendConn, sentinelConn := net.Pipe()
	backendSession, err := yamux.Server(backendConn, nil)
	require.NoError(t, err)
	sentinelSession, err := yamux.Client(sentinelConn, nil)
	require.NoError(t, err)
	return sentinelSession, func() {
		_ = sentinelSession.Close()
		_ = backendSession.Close()
		_ = sentinelConn.Close()
		_ = backendConn.Close()
	}
}

// freeLoopbackPort returns a loopback port that is free right now.
//
// TestMonitorSessionCleansUpCurrentGeneration named port 8080, which
// startProxies binds as-is. Anything else on the machine holding 8080 — a
// container port-forward, a dev server — made it fail with "Should NOT be
// empty, but was []", an assertion about listeners that reads as a bug in the
// code under test rather than as a busy port.
//
// There is a small window between closing this listener and the code under
// test binding the port, which is unavoidable without threading a listener
// through. It is a much smaller risk than naming a port something else is
// probably using.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// requireListeners fails if the spot has no proxy listeners.
//
// TestMonitorSessionIgnoresSupersededGeneration asserted nothing about
// listeners, so a future failure to bind would leave it exercising the
// no-listeners path and still passing. It was not doing so before this
// change — its ports are remapped out of the privileged range — but nothing
// was stopping it.
func requireListeners(t *testing.T, ts *TunnelServer, spotID string) {
	t.Helper()
	ts.mu.Lock()
	defer ts.mu.Unlock()
	p, ok := ts.proxies[spotID]
	require.True(t, ok, "no proxies recorded for %s — startProxies bound nothing", spotID)
	require.NotEmpty(t, p.listeners,
		"%s has no listeners: the port was busy, so this test would exercise the "+
			"no-listeners path rather than the one it is written for", spotID)
}

func handshake(spotID string) *TunnelHandshake {
	return &TunnelHandshake{SpotID: spotID, Ports: []int{22, 8080}, Pool: "prod"}
}

// closeProxiesOnCleanup releases every listener the server installed. Proxy
// listen ports are derived from the remote port (fixed, e.g. 22 -> 20022), so
// without this a test leaves a bound port behind and the next one silently
// gets zero listeners.
func closeProxiesOnCleanup(t *testing.T, ts *TunnelServer) {
	t.Helper()
	t.Cleanup(func() {
		ts.mu.Lock()
		defer ts.mu.Unlock()
		for id := range ts.proxies {
			ts.closeProxiesLocked(id)
		}
	})
}

// TestReconnectKeepsTheNewRegistration is the #769 regression. Without the
// generation guard the stale monitor unregisters the spot, so the backend
// disappears from the registry while its tunnel is up.
func TestReconnectKeepsTheNewRegistration(t *testing.T) {
	stubLoopbackAliases(t)
	r := NewTunnelRegistry()

	firstSession, closeFirst := newSessionPair(t)
	defer closeFirst()
	firstIP, firstGen, err := r.Register(handshake("spot-1"), firstSession)
	require.NoError(t, err)

	// The backend reboots and reconnects under the same id. Register closes
	// the previous session as part of replacing it.
	secondSession, closeSecond := newSessionPair(t)
	defer closeSecond()
	secondIP, secondGen, err := r.Register(handshake("spot-1"), secondSession)
	require.NoError(t, err)

	require.Equal(t, firstIP, secondIP, "a reconnect must reuse the loopback alias, or sshpiper's config goes stale")
	require.Greater(t, secondGen, firstGen, "each registration needs a distinct generation to be distinguishable")

	// The stale watcher now wakes up and tries to clean up. It must decline.
	removed := r.UnregisterIfCurrent("spot-1", firstGen)
	require.Nil(t, removed,
		"the superseded registration must not unregister the one that replaced it — this is #769")

	live := r.Get("spot-1")
	require.NotNil(t, live, "the spot must still be registered after its own reconnect")
	require.Equal(t, secondGen, live.Generation)
	require.Same(t, secondSession, live.Session, "the registry must point at the NEW session")
}

// A genuine disconnect must still clean up — the guard must not turn the
// teardown path into a no-op.
func TestGenuineDisconnectStillUnregisters(t *testing.T) {
	stubLoopbackAliases(t)
	r := NewTunnelRegistry()

	session, closeSession := newSessionPair(t)
	defer closeSession()
	_, gen, err := r.Register(handshake("spot-1"), session)
	require.NoError(t, err)

	removed := r.UnregisterIfCurrent("spot-1", gen)
	require.NotNil(t, removed, "the current generation must be able to unregister itself")
	require.Nil(t, r.Get("spot-1"))

	// Idempotent: a second cleanup for the same generation finds nothing.
	require.Nil(t, r.UnregisterIfCurrent("spot-1", gen))
}

// TestMonitorSessionIgnoresSupersededGeneration drives the real code path:
// startProxies + monitorSession, with a reconnect in between. Without the
// guard the stale monitor closes the fresh listeners and fires OnDisconnect
// for a backend that is up — which in production strips that backend's users
// out of the sshpiper config (Manager.OnTunnelDisconnect) and is exactly why
// container SSH stayed broken until the sentinel was restarted.
func TestMonitorSessionIgnoresSupersededGeneration(t *testing.T) {
	stubLoopbackAliases(t)

	registry := NewTunnelRegistry()
	ts := NewTunnelServer("127.0.0.1:0", NewTokenPolicy(), registry)
	closeProxiesOnCleanup(t, ts)

	var mu sync.Mutex
	var disconnects []string
	ts.OnDisconnect = func(spot *TunnelSpot) {
		mu.Lock()
		defer mu.Unlock()
		disconnects = append(disconnects, spot.ID)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First registration, with its listeners and its monitor.
	firstSession, closeFirst := newSessionPair(t)
	defer closeFirst()
	_, firstGen, err := registry.Register(handshake("spot-1"), firstSession)
	require.NoError(t, err)
	// Bind on 127.0.0.1 rather than the (stubbed, non-existent) alias, and on
	// a port picked at run time rather than named here. A privileged remote
	// port is remapped by startProxies (22 becomes 20022), but an unprivileged
	// one is bound as-is — so naming a port means the test fails whenever a
	// developer happens to be running anything on it.
	proxyPort := freeLoopbackPort(t)
	ts.startProxies(ctx, "spot-1", firstGen, "127.0.0.1", 0, []int{proxyPort}, firstSession)
	requireListeners(t, ts, "spot-1")

	monitorDone := make(chan struct{})
	go func() {
		ts.monitorSession("spot-1", firstGen, firstSession)
		close(monitorDone)
	}()

	// Reconnect: Register closes firstSession, which wakes the monitor above.
	secondSession, closeSecond := newSessionPair(t)
	defer closeSecond()
	_, secondGen, err := registry.Register(handshake("spot-1"), secondSession)
	require.NoError(t, err)
	// The same port as the first registration: a reconnect rebinds what the
	// superseded generation had.
	ts.startProxies(ctx, "spot-1", secondGen, "127.0.0.1", 0, []int{proxyPort}, secondSession)

	select {
	case <-monitorDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the monitor for the superseded session never returned")
	}

	// The spot is still registered, on the new generation.
	live := registry.Get("spot-1")
	require.NotNil(t, live, "the stale monitor unregistered a live backend — #769")
	require.Equal(t, secondGen, live.Generation)

	// Its listeners are still the new generation's, and still open.
	ts.mu.Lock()
	set, ok := ts.proxies["spot-1"]
	ts.mu.Unlock()
	require.True(t, ok, "the stale monitor closed the fresh registration's proxy listeners — #769")
	require.Equal(t, secondGen, set.gen)
	require.NotEmpty(t, set.listeners)
	for _, ln := range set.listeners {
		conn, dialErr := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		require.NoError(t, dialErr, "a listener installed by the live registration must still accept connections")
		_ = conn.Close()
	}

	// And the manager was never told the backend went away — that callback is
	// what removes the backend's users from the sshpiper config.
	mu.Lock()
	got := append([]string(nil), disconnects...)
	mu.Unlock()
	require.Empty(t, got, "OnDisconnect fired for a backend whose tunnel is up — sshpiper would drop its users")
}

// The mirror case: when the CURRENT session ends, the monitor must do the full
// teardown, including telling the manager.
func TestMonitorSessionCleansUpCurrentGeneration(t *testing.T) {
	stubLoopbackAliases(t)

	registry := NewTunnelRegistry()
	ts := NewTunnelServer("127.0.0.1:0", NewTokenPolicy(), registry)
	closeProxiesOnCleanup(t, ts)

	disconnected := make(chan string, 1)
	ts.OnDisconnect = func(spot *TunnelSpot) { disconnected <- spot.ID }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session, closeSession := newSessionPair(t)
	defer closeSession()
	_, gen, err := registry.Register(handshake("spot-1"), session)
	require.NoError(t, err)
	ts.startProxies(ctx, "spot-1", gen, "127.0.0.1", 0, []int{freeLoopbackPort(t)}, session)

	ts.mu.Lock()
	listeners := append([]net.Listener(nil), ts.proxies["spot-1"].listeners...)
	ts.mu.Unlock()
	require.NotEmpty(t, listeners)

	go ts.monitorSession("spot-1", gen, session)

	// A real disconnect.
	_ = session.Close()

	select {
	case id := <-disconnected:
		require.Equal(t, "spot-1", id)
	case <-time.After(5 * time.Second):
		t.Fatal("a genuine disconnect did not reach OnDisconnect")
	}

	require.Nil(t, registry.Get("spot-1"), "a genuine disconnect must unregister the spot")

	ts.mu.Lock()
	_, stillThere := ts.proxies["spot-1"]
	ts.mu.Unlock()
	require.False(t, stillThere, "a genuine disconnect must drop the proxy listeners")

	for _, ln := range listeners {
		_, dialErr := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
		require.Error(t, dialErr, "listeners must actually be closed, not just forgotten")
	}
}

// startProxies must not let a late, superseded call clobber the listeners a
// newer registration already installed.
func TestStartProxiesRefusesToClobberANewerGeneration(t *testing.T) {
	stubLoopbackAliases(t)

	registry := NewTunnelRegistry()
	ts := NewTunnelServer("127.0.0.1:0", NewTokenPolicy(), registry)
	closeProxiesOnCleanup(t, ts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session, closeSession := newSessionPair(t)
	defer closeSession()

	// Picked at run time, not named: 9090 is Prometheus's default and is
	// plausibly in use on a developer machine. Both calls share it because the
	// point is that the second, staler one must not take over the first's
	// listener on the same port.
	proxyPort := freeLoopbackPort(t)

	ts.startProxies(ctx, "spot-1", 7, "127.0.0.1", 0, []int{proxyPort}, session)
	ts.mu.Lock()
	current := ts.proxies["spot-1"]
	ts.mu.Unlock()
	require.Equal(t, uint64(7), current.gen)
	require.NotEmpty(t, current.listeners)

	// An older registration's call arriving late must be ignored outright.
	ts.startProxies(ctx, "spot-1", 3, "127.0.0.1", 0, []int{proxyPort}, session)

	ts.mu.Lock()
	after := ts.proxies["spot-1"]
	ts.mu.Unlock()
	require.Equal(t, uint64(7), after.gen, "a stale startProxies replaced the live generation's listeners")

	conn, err := net.DialTimeout("tcp", after.listeners[0].Addr().String(), 2*time.Second)
	require.NoError(t, err, "the live generation's listener must still be open")
	_ = conn.Close()
}
