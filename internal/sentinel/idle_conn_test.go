package sentinel

import (
	"crypto/tls"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIdleTimeoutConn_TimesOutWhenNoDataArrives (#1349): a Read that would
// otherwise block forever (no bytes, no EOF, no error — the shape a
// vanished peer with no FIN/RST leaves a connection in) must return a
// timeout error once the idle window elapses.
func TestIdleTimeoutConn_TimesOutWhenNoDataArrives(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	// Nothing is ever written on the client side, and neither end is
	// closed — exactly what a peer that vanished without FIN/RST looks
	// like from the other side's Read.

	c := &idleTimeoutConn{Conn: server, idleTimeout: 30 * time.Millisecond}

	start := time.Now()
	_, err := c.Read(make([]byte, 16))
	elapsed := time.Since(start)

	require.Error(t, err, "Read on a silent peer must not block forever")
	var netErr net.Error
	if assert.ErrorAs(t, err, &netErr) {
		assert.True(t, netErr.Timeout(), "error must report Timeout() so io.Copy's caller can tell an idle peer from a real failure")
	}
	assert.Less(t, elapsed, time.Second, "must not have blocked long past the idle timeout")
}

// TestIdleTimeoutConn_RefreshesOnEveryRead (#1349): the deadline must be a
// rolling idle window, not a fixed lifetime for the connection — an
// actively-chattering peer, however slowly, must never see a timeout.
func TestIdleTimeoutConn_RefreshesOnEveryRead(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	const idle = 40 * time.Millisecond
	c := &idleTimeoutConn{Conn: server, idleTimeout: idle}

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		// Writes spaced well inside the idle window, for well past it in
		// total — if the deadline were fixed at connection-open instead
		// of refreshed per read, this would still time out partway
		// through.
		for i := 0; i < 6; i++ {
			select {
			case <-stop:
				return
			case <-time.After(idle / 2):
			}
			if _, err := client.Write([]byte("x")); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 1)
	for i := 0; i < 6; i++ {
		n, err := c.Read(buf)
		require.NoErrorf(t, err, "read %d timed out despite ongoing activity", i)
		require.Equal(t, 1, n)
	}
}

// TestSNIRouting_VanishedBackendDoesNotLeakGoroutines (#1349): reproduces
// the incident directly. A "backend" accepts the sentinel's connection
// and then never reads, writes, or closes it — a powered-off or
// preempted host never sends FIN/RST, so from the sentinel's side the
// connection looks identical to one whose peer is still there but
// silent. The client side is held open (not closed) too, so BOTH
// io.Copy directions in buildSNIRoutingHandler have nothing to return
// on naturally — before #1349's fix, this hangs the handler and its two
// copy goroutines (plus peekSNI's bufio.Reader and both 32KB copy
// buffers) forever, exactly as profiled in production (2,730 leaked
// pairs, ~330MB in 35 minutes). With the fix, the idle timeout forces
// both goroutines to return well within the test's bound.
func TestSNIRouting_VanishedBackendDoesNotLeakGoroutines(t *testing.T) {
	// The "backend": accepts once, then holds the connection open and
	// silent — never sends, never closes. Simulates a host that vanished
	// without FIN/RST.
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = backendLn.Close() }()
	backendAccepted := make(chan net.Conn, 1)
	go func() {
		conn, err := backendLn.Accept()
		if err == nil {
			backendAccepted <- conn
		}
	}()

	m := &Manager{
		primaries:        NewPrimaryRegistry(),
		proxyIdleTimeout: 50 * time.Millisecond,
	}
	handler := m.buildSNIRoutingHandler(backendLn.Addr().String())

	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = frontLn.Close() }()

	handlerDone := make(chan struct{})
	go func() {
		serverConn, err := frontLn.Accept()
		if err != nil {
			close(handlerDone)
			return
		}
		handler(serverConn)
		close(handlerDone)
	}()

	before := runtime.NumGoroutine()

	clientConn, err := net.Dial("tcp", frontLn.Addr().String())
	require.NoError(t, err)
	defer func() { _ = clientConn.Close() }()

	// The backend never sends a ServerHello (it does nothing at all), so
	// a real Handshake() can never complete — same as
	// TestExtractSNI_RealClientHello, fire it in the background just to
	// put real ClientHello bytes on the wire for peekSNI, and don't wait
	// on (or care about) its outcome. The client then goes silent too —
	// no more writes, no close — so nothing but the idle timeout can end
	// this on either side.
	go func() {
		_ = tls.Client(clientConn, &tls.Config{ServerName: "stranger.example", InsecureSkipVerify: true}).Handshake()
	}()

	select {
	case backend := <-backendAccepted:
		defer func() { _ = backend.Close() }()
		// Deliberately do nothing with it — no read, no write, no close.
	case <-time.After(2 * time.Second):
		t.Fatal("backend never accepted the forwarded connection")
	}

	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("buildSNIRoutingHandler never returned — the vanished-peer connection leaked " +
			"exactly as in #1349, instead of timing out")
	}

	// Give the two copy goroutines a moment past the handler's own
	// return to actually unwind (their final Read/Write calls racing
	// the deferred Close), then confirm nothing outlived them.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	after := runtime.NumGoroutine()
	assert.LessOrEqualf(t, after, before+2, "goroutine count grew from %d to %d and stayed there — "+
		"the vanished backend's connection was not fully cleaned up", before, after)
}
