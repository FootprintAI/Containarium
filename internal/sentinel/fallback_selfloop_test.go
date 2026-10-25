package sentinel

import (
	"crypto/tls"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// acceptCountListener counts accepted connections so a test can see how many
// hops one client connection fans out into.
type acceptCountListener struct {
	net.Listener
	accepted atomic.Int64
}

func (c *acceptCountListener) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil {
		c.accepted.Add(1)
	}
	return conn, err
}

// TestFallbackToOwnListenerIsRefused guards the production failure where the
// passthrough fallback was a tunnel backend's loopback alias (127.0.0.N:443).
// The ConnMux listens on the wildcard :443, so that dial connects back to the
// sentinel; the connection is routed again, falls back again, and a SINGLE
// client connection fans out into an unbounded chain (about 100 KB per hop;
// tens of thousands of hops within seconds). With the 384M cgroup cap that is a
// sentinel OOM kill a fraction of a second after the first unmatched
// connection, every time a failover lands on a tunnel backend.
//
// Here 127.0.0.1 plays the alias and the mux's own port plays :443. The handler
// must refuse to dial it, so the one client connection stays one connection.
func TestFallbackToOwnListenerIsRefused(t *testing.T) {
	// Goroutines other tests started and have not finished stopping are not
	// this test's to account for, and a fixed ceiling grows with every -count
	// repetition. Measure what THIS test adds on top of where it began.
	baseline := settledGoroutines()

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln := &acceptCountListener{Listener: rawLn}
	mux := NewConnMuxFromListener(ln)
	go mux.Run()
	defer func() { _ = mux.Close() }()

	muxPort := rawLn.Addr().(*net.TCPAddr).Port
	dl := newDispatchListener(mux.HTTPSChanListener())
	m := &Manager{
		primaries:        NewPrimaryRegistry(),
		proxyIdleTimeout: 120 * time.Second, // production sniProxyIdleTimeout
		config:           Config{ProxyProtocol: true, HTTPSPort: muxPort},
	}
	// The fallback is the mux's own address, exactly like fallback=<alias>:443.
	dl.SetHandler(m.buildSNIRoutingHandler(rawLn.Addr().String()))

	client, err := net.Dial("tcp", rawLn.Addr().String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: "unregistered.example", InsecureSkipVerify: true}).Handshake()
	}()

	// Unfixed, this reaches thousands of accepts within 100 ms. Wait well past
	// that, then require the client connection to be the only one.
	time.Sleep(750 * time.Millisecond)
	assert.LessOrEqualf(t, ln.accepted.Load(), int64(2),
		"one client connection produced %d accepted connections: the fallback is looping back into the sentinel's own listener",
		ln.accepted.Load())

	// Tear down everything this test started, then require the process to
	// return to where it began. A fallback that leaked a goroutine per hop
	// (or kept the looped connections open) would stay above the baseline.
	_ = client.Close()
	_ = mux.Close()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	assert.LessOrEqual(t, runtime.NumGoroutine(), baseline, "goroutines did not settle back to the count at the start of the test after the refused fallback")
}

// settledGoroutines returns runtime.NumGoroutine() once it has stopped
// falling, so goroutines still winding down from an earlier test do not
// inflate a baseline.
func settledGoroutines() int {
	prev := runtime.NumGoroutine()
	stable := 0
	deadline := time.Now().Add(2 * time.Second)
	for stable < 5 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		cur := runtime.NumGoroutine()
		if cur >= prev {
			stable++
		} else {
			stable = 0
		}
		prev = cur
	}
	return prev
}

// TestIsOwnHTTPSListener pins which targets count as "ourselves".
func TestIsOwnHTTPSListener(t *testing.T) {
	m := &Manager{config: Config{HTTPSPort: 443}}
	for target, want := range map[string]bool{
		"127.0.0.2:443":          true,  // tunnel backend alias on the HTTPS port
		"127.0.0.188:443":        true,  // another alias
		"127.0.0.1:443":          true,  // plain loopback
		"[::1]:443":              true,  // IPv6 loopback
		"[::1%lo]:443":           true,  // IPv6 loopback with a zone identifier
		"[::ffff:127.0.0.2]:443": true,  // IPv4-mapped loopback
		"127.0.0.2:8080":         false, // loopback, but not the mux port
		"10.140.0.51:443":        false, // a real remote backend
		"not-a-host-port":        false,
		"":                       false,
		"127.0.0.2:notnum":       false,
	} {
		assert.Equalf(t, want, m.isOwnHTTPSListener(target), "target %q", target)
	}
	// Unset port (tests, non-ConnMux modes) never matches.
	assert.False(t, (&Manager{}).isOwnHTTPSListener("127.0.0.2:443"))
}

// TestStartHTTPSProxy_TunnelBackendFallsBackThroughTunnel checks that when the
// elected backend is a tunnel backend, traffic matching no primary reaches it
// through its yamux session (as a tunnel-promoted primary already does) and
// NOT through a TCP dial to its loopback alias.
func TestStartHTTPSProxy_TunnelBackendFallsBackThroughTunnel(t *testing.T) {
	remoteAddr, remoteHits := startEchoListener(t, "TUNNEL-BACKEND")
	_, remotePortStr, _ := net.SplitHostPort(remoteAddr)
	remotePort := mustAtoi(t, remotePortStr)

	// A real yamux pair: the "spot" side reads the 2-byte port header and
	// proxies to the echo server, as the tunnel client does.
	spotConn, sentinelConn := net.Pipe()
	defer func() { _ = spotConn.Close() }()
	defer func() { _ = sentinelConn.Close() }()
	spotSession, err := yamux.Server(spotConn, nil)
	require.NoError(t, err)
	sentinelSession, err := yamux.Client(sentinelConn, nil)
	require.NoError(t, err)
	defer func() { _ = spotSession.Close() }()
	defer func() { _ = sentinelSession.Close() }()
	go func() {
		for {
			s, err := spotSession.Accept()
			if err != nil {
				return
			}
			go func(stream net.Conn) {
				defer func() { _ = stream.Close() }()
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(stream, hdr); err != nil {
					return
				}
				if int(hdr[0])<<8|int(hdr[1]) != remotePort {
					return
				}
				up, err := net.Dial("tcp", remoteAddr)
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(up, stream); done <- struct{}{} }()
				go func() { _, _ = io.Copy(stream, up); done <- struct{}{} }()
				<-done
			}(s)
		}
	}()

	tr := NewTunnelRegistry()
	tr.spots["lab-1"] = &TunnelSpot{ID: "lab-1", Session: sentinelSession, LocalIP: "127.0.0.77"}

	m := &Manager{
		primaries:      NewPrimaryRegistry(),
		tunnelRegistry: tr,
		config:         Config{HTTPSPort: remotePort},
	}
	m.httpsDispatch = newDispatchListener(newChanListener(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}))

	// IP is a loopback alias nothing listens on: a TCP dial to it cannot work,
	// so reaching the echo server proves the yamux path was used.
	m.startHTTPSProxy(&Backend{ID: "tunnel-lab-1", Type: BackendTunnel, IP: "127.0.0.77"})

	m.httpsDispatch.mu.RLock()
	handler := m.httpsDispatch.handler
	m.httpsDispatch.mu.RUnlock()
	require.NotNil(t, handler)

	got := dialThroughHandler(t, handler, &tls.Config{ServerName: "stranger.example", InsecureSkipVerify: true})
	assert.Equal(t, "TUNNEL-BACKEND", got, "an unmatched connection must fall back through the tunnel")
	assert.Equal(t, 1, remoteHits())
}

// TestFallbackHostnameToOwnListenerIsRefused covers a target that is not an IP
// literal: "localhost" passes the literal check, so the refusal has to come from
// the connected socket's remote address. The handler may open one connection to
// find that out, but must not keep the chain going.
func TestFallbackHostnameToOwnListenerIsRefused(t *testing.T) {
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln := &acceptCountListener{Listener: rawLn}
	mux := NewConnMuxFromListener(ln)
	go mux.Run()
	defer func() { _ = mux.Close() }()

	muxPort := rawLn.Addr().(*net.TCPAddr).Port
	dl := newDispatchListener(mux.HTTPSChanListener())
	m := &Manager{
		primaries:        NewPrimaryRegistry(),
		proxyIdleTimeout: 120 * time.Second,
		config:           Config{ProxyProtocol: true, HTTPSPort: muxPort},
	}
	dl.SetHandler(m.buildSNIRoutingHandler(net.JoinHostPort("localhost", strconv.Itoa(muxPort))))

	client, err := net.Dial("tcp", rawLn.Addr().String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: "unregistered.example", InsecureSkipVerify: true}).Handshake()
	}()

	time.Sleep(750 * time.Millisecond)
	assert.LessOrEqualf(t, ln.accepted.Load(), int64(3),
		"a hostname fallback that resolves to the sentinel's own listener produced %d accepted connections", ln.accepted.Load())
}

// TestPrimaryOnOwnListenerFallsThroughToFallback checks the matched-primary TCP
// path: a primary registered with a loopback IP on the HTTPS port is refused
// (it would be the mux itself) and the connection takes the fallback instead.
func TestPrimaryOnOwnListenerFallsThroughToFallback(t *testing.T) {
	fallbackAddr, fallbackHits := startEchoListener(t, "FALLBACK")

	const httpsPort = 4433 // nothing listens here; the refusal must happen before any dial
	m := &Manager{
		primaries: NewPrimaryRegistry(),
		config:    Config{HTTPSPort: httpsPort},
	}
	m.primaries.Register(Primary{Pool: "p", Hostname: "looped.example", IP: "127.0.0.1", Port: httpsPort})

	handler := m.buildSNIRoutingHandler(fallbackAddr)
	got := dialThroughHandler(t, handler, &tls.Config{ServerName: "looped.example", InsecureSkipVerify: true})
	assert.Equal(t, "FALLBACK", got, "a primary that points at our own listener must not be dialled")
	assert.Equal(t, 1, fallbackHits())
}
