package sentinel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// dialToTestServer builds a dial func that ignores spotID/port (the real
// DialTunnel routes by those; here we just need "the tunnel" to land on a
// local httptest server) and always connects to ts's listener — mirroring
// how a real tunnel client would forward to whatever's on the primary's
// local port, without needing a real yamux session in these tests.
func dialToTestServer(t *testing.T, ts *httptest.Server) func(spotID string, port int) (net.Conn, error) {
	t.Helper()
	addr := strings.TrimPrefix(strings.TrimPrefix(ts.URL, "https://"), "http://")
	return func(string, int) (net.Conn, error) {
		return net.Dial("tcp", addr)
	}
}

// hostRoutedServer starts a TLS test server whose handler mimics a
// misconfigured Caddy: it answers 200 for hosts in `ok`, and 502 (with a
// Caddy-branded body, matching the real symptom in #1872) for anything
// else.
func hostRoutedServer(t *testing.T, ok ...string) *httptest.Server {
	t.Helper()
	allowed := make(map[string]bool, len(ok))
	for _, h := range ok {
		allowed[h] = true
	}
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowed[r.Host] {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Server", "Caddy")
		w.WriteHeader(http.StatusBadGateway)
	}))
}

func TestProbeHostname_ReachableOn200(t *testing.T) {
	ts := hostRoutedServer(t, "facelabor.kafeido.app")
	defer ts.Close()

	health := probeHostname(dialToTestServer(t, ts), "spot-1", 443, "facelabor.kafeido.app", 2*time.Second)
	assert.True(t, health.Reachable)
	assert.Empty(t, health.Error)
	assert.Equal(t, "facelabor.kafeido.app", health.Hostname)
	assert.False(t, health.CheckedAt.IsZero())
}

// TestProbeHostname_UnreachableOn502 is the regression test for #1872's
// exact symptom: the sentinel successfully dials the tunnel and completes
// a TLS handshake (registration "looks" fine), but the primary's own
// Caddy has no route for this particular alias and answers 502.
func TestProbeHostname_UnreachableOn502(t *testing.T) {
	ts := hostRoutedServer(t, "facelabor.kafeido.app") // grpc.kafeido.app NOT configured
	defer ts.Close()

	health := probeHostname(dialToTestServer(t, ts), "spot-1", 443, "grpc.kafeido.app", 2*time.Second)
	assert.False(t, health.Reachable)
	assert.Contains(t, health.Error, "502")
}

func TestProbeHostname_DialFailureIsUnreachable(t *testing.T) {
	dial := func(string, int) (net.Conn, error) {
		return nil, assertErr("spot not registered")
	}
	health := probeHostname(dial, "spot-1", 443, "grpc.kafeido.app", 2*time.Second)
	assert.False(t, health.Reachable)
	assert.Contains(t, health.Error, "dial")
}

func TestProbeHostname_HandshakeFailureIsUnreachable(t *testing.T) {
	// A listener that accepts and immediately closes, so the TLS handshake
	// fails outright — simulating a dead/non-TLS port on the primary.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	dial := func(string, int) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	}
	health := probeHostname(dial, "spot-1", 443, "grpc.kafeido.app", 2*time.Second)
	assert.False(t, health.Reachable)
	assert.Contains(t, health.Error, "handshake")
}

// TestDialWithTimeout_BoundsABlockedDial is the regression test for the
// CodeRabbit finding on PR #1873: DialTunnel's underlying yamux
// Session.Open() has no context/deadline of its own, so a dial that never
// returns (the SYN-limit-blocked case in production) must still be
// bounded by the probe's timeout rather than hanging the whole sweep.
func TestDialWithTimeout_BoundsABlockedDial(t *testing.T) {
	block := make(chan struct{})
	dial := func(string, int) (net.Conn, error) {
		<-block // never returns within the test
		return nil, nil
	}
	defer close(block)

	start := time.Now()
	_, err := dialWithTimeout(dial, "spot-1", 443, 100*time.Millisecond)
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.Less(t, elapsed, time.Second, "dialWithTimeout must return promptly, not wait for dial")
}

// TestDialWithTimeout_LateArrivingConnIsClosed proves a dial that finally
// resolves after the timeout doesn't leak its connection.
func TestDialWithTimeout_LateArrivingConnIsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	release := make(chan struct{})
	dial := func(string, int) (net.Conn, error) {
		<-release // resolves only after dialWithTimeout has already given up
		return net.Dial("tcp", ln.Addr().String())
	}

	_, err = dialWithTimeout(dial, "spot-1", 443, 50*time.Millisecond)
	assert.Error(t, err, "must time out while dial is still blocked")
	close(release)

	select {
	case serverSide := <-accepted:
		// The late-arriving client conn should get closed by
		// dialWithTimeout's cleanup goroutine, which the server side
		// observes as EOF/closed rather than staying open forever.
		buf := make([]byte, 1)
		_ = serverSide.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, readErr := serverSide.Read(buf)
		assert.Error(t, readErr, "server side should see the late client conn close, not hang open")
		_ = serverSide.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("dial never reached the local listener")
	}
}

type assertErr string

func (e assertErr) Error() string { return string(e) }

// TestCheckTunnelPrimaries_RecordsPerHostnameResults is the end-to-end
// regression test for #1872: one tunnel-promoted primary whose Hostname is
// correctly served but whose Alias is not (the exact prod-kafeido shape)
// must come out of the sweep with per-hostname results, not a single
// pass/fail for the whole primary.
func TestCheckTunnelPrimaries_RecordsPerHostnameResults(t *testing.T) {
	ts := hostRoutedServer(t, "facelabor.kafeido.app")
	defer ts.Close()

	m := &Manager{primaries: NewPrimaryRegistry()}
	m.reachabilityDial = dialToTestServer(t, ts)
	m.primaries.Register(Primary{
		Pool:      "prod-kafeido",
		Hostname:  "facelabor.kafeido.app",
		Aliases:   []string{"grpc.kafeido.app"},
		IP:        "127.0.0.2",
		Port:      443,
		BackendID: "tunnel-ase1-spot-prod",
	})

	m.checkTunnelPrimaries(context.Background())

	p := m.primaries.LookupByPool("prod-kafeido")
	if assert.NotNil(t, p) {
		assert.Len(t, p.AliasHealth, 2)
		byHost := map[string]AliasHealth{}
		for _, h := range p.AliasHealth {
			byHost[h.Hostname] = h
		}
		if assert.Contains(t, byHost, "facelabor.kafeido.app") {
			assert.True(t, byHost["facelabor.kafeido.app"].Reachable)
		}
		if assert.Contains(t, byHost, "grpc.kafeido.app") {
			assert.False(t, byHost["grpc.kafeido.app"].Reachable)
			assert.Contains(t, byHost["grpc.kafeido.app"].Error, "502")
		}
	}
}

// TestCheckTunnelPrimaries_SkipsInVPCPrimaries: a primary registered via
// the legacy HTTP path (BackendID empty) is routed through Caddy's
// layer4/routes table, not the tunnel — it must never be dialed here.
func TestCheckTunnelPrimaries_SkipsInVPCPrimaries(t *testing.T) {
	m := &Manager{primaries: NewPrimaryRegistry()}
	dialCalls := 0
	m.reachabilityDial = func(string, int) (net.Conn, error) {
		dialCalls++
		return nil, assertErr("must not be called for an in-VPC primary")
	}
	m.primaries.Register(Primary{
		Pool:     "legacy",
		Hostname: "legacy.example.com",
		IP:       "10.0.0.10",
		Port:     443,
	})

	m.checkTunnelPrimaries(context.Background())

	assert.Equal(t, 0, dialCalls)
	p := m.primaries.LookupByPool("legacy")
	if assert.NotNil(t, p) {
		assert.Empty(t, p.AliasHealth)
	}
}

func TestCheckTunnelPrimaries_NoOpWithoutADialer(t *testing.T) {
	m := &Manager{primaries: NewPrimaryRegistry()}
	m.primaries.Register(Primary{
		Pool:      "prod",
		Hostname:  "prod.example.com",
		IP:        "127.0.0.2",
		Port:      443,
		BackendID: "tunnel-spot-1",
	})

	// Neither reachabilityDial nor tunnelRegistry is set — must not panic,
	// must leave AliasHealth untouched.
	m.checkTunnelPrimaries(context.Background())

	p := m.primaries.LookupByPool("prod")
	if assert.NotNil(t, p) {
		assert.Empty(t, p.AliasHealth)
	}
}

func TestRunPrimaryReachabilityLoop_NoOpWithoutTunnelRegistry(t *testing.T) {
	m := &Manager{primaries: NewPrimaryRegistry()}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		m.runPrimaryReachabilityLoop(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runPrimaryReachabilityLoop did not return promptly without a tunnel registry")
	}
}
