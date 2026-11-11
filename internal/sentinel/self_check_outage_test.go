package sentinel

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Exercise the real ClientHello -> ConnMux -> dispatch -> SNI path. The
// backend accepts TCP but never answers TLS, as an outage can leave the
// application path stalled while the separate management port stays healthy.
func TestSelfCheck_BackendOutageDoesNotTriggerExit(t *testing.T) {
	for _, route := range []string{"fallback", "primary", "base-domain"} {
		t.Run(route, func(t *testing.T) {
			backend := newWedgedListener(t)
			defer func() { _ = backend.Close() }()

			m := routingSelfCheckManager(t, backend.ln.Addr().String())
			if route != "fallback" {
				p := Primary{Pool: "test", Hostname: "backend.example", IP: "127.0.0.1", Port: backend.port}
				if route == "primary" {
					p.Aliases = []string{selfCheckSNI}
				} else {
					p.BaseDomains = []string{"invalid"}
				}
				m.primaries.Register(p)
			}

			exits := 0
			m.exitFn = func() { exits++ }
			m.selfCheckFn = func() error { return m.selfCheckProxyPath(300 * time.Millisecond) }
			failures := 0
			for range m.config.SelfCheckFailureThreshold + 1 {
				var triggered bool
				failures, triggered = m.selfCheckOnce(failures)
				if triggered {
					break
				}
			}
			require.Zero(t, exits, "a backend outage must not restart the sentinel (#1139)")
			require.Zero(t, failures, "the local pipeline serviced the probe; backend health is independent")

			backend.mu.Lock()
			dials := len(backend.conns)
			backend.mu.Unlock()
			require.Zero(t, dials, "self-check traffic must never reach a tenant backend")
		})
	}
}

// Refusing the probe at the router must still require the mux and dispatch
// to service it. A genuinely stalled local dispatch must retain its watchdog.
func TestSelfCheck_UnservicedDispatchStillTriggersExit(t *testing.T) {
	m := routingSelfCheckManager(t, "127.0.0.1:1")
	blocked := make(chan struct{})
	defer close(blocked)
	m.httpsDispatch.SetHandler(func(conn net.Conn) {
		<-blocked
		_ = conn.Close()
	})
	exits := 0
	m.exitFn = func() { exits++ }
	m.selfCheckFn = func() error { return m.selfCheckProxyPath(300 * time.Millisecond) }
	failures := 0
	for range m.config.SelfCheckFailureThreshold {
		failures, _ = m.selfCheckOnce(failures)
	}
	require.Equal(t, 1, exits, "a stalled local pipeline must still trigger recovery")
}

func routingSelfCheckManager(t *testing.T, fallback string) *Manager {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mux := NewConnMuxFromListener(ln)
	done := make(chan struct{})
	go func() {
		mux.Run()
		close(done)
	}()
	t.Cleanup(func() {
		_ = mux.Close()
		<-done
	})

	m := &Manager{
		config: Config{
			HTTPSPort:                 ln.Addr().(*net.TCPAddr).Port,
			SelfCheckFailureThreshold: 3,
		},
		primaries: NewPrimaryRegistry(),
	}
	m.state.Store(StateProxy)
	m.httpsDispatch = newDispatchListener(mux.HTTPSChanListener())
	m.httpsDispatch.SetHandler(m.buildSNIRoutingHandler(fallback))
	return m
}
