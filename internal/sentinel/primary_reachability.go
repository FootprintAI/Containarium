package sentinel

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// defaultReachabilityInterval is how often checkTunnelPrimaries sweeps
// every tunnel-promoted primary when Config.PrimaryReachabilityInterval
// is unset.
const defaultReachabilityInterval = 30 * time.Second

// defaultReachabilityTimeout bounds one probeHostname call (dial + TLS
// handshake + one HTTP round trip) so a wedged spot can't stall the sweep.
const defaultReachabilityTimeout = 10 * time.Second

// dialWithTimeout bounds dial's own runtime to timeout. This matters
// because DialTunnel's stream open (yamux Session.Open()) takes no context
// or deadline of its own — on a session that has hit yamux's in-flight-SYN
// limit, Open() can block until the session closes, well past the
// deadline probeHostname sets on the returned conn (which only starts
// after dial returns). Without this wrapper a single wedged tunnel could
// stall the whole reachability sweep indefinitely despite the advertised
// per-hostname timeout.
//
// If dial is still running when timeout fires, it's left to finish in the
// background; if it eventually succeeds, the resulting conn is closed
// immediately rather than left dangling.
func dialWithTimeout(dial func(spotID string, port int) (net.Conn, error), spotID string, port int, timeout time.Duration) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := dial(spotID, port)
		ch <- result{conn, err}
	}()

	select {
	case res := <-ch:
		return res.conn, res.err
	case <-time.After(timeout):
		go func() {
			if res := <-ch; res.conn != nil {
				_ = res.conn.Close()
			}
		}()
		return nil, fmt.Errorf("timed out after %s opening a stream to spot %q", timeout, spotID)
	}
}

// probeHostname dials spotID's port over the tunnel via dial, completes a
// TLS handshake presenting hostname as SNI, then sends a bare HTTP/1.1 GET
// and inspects the status line.
//
// InsecureSkipVerify is correct here, not a weakening: this probe runs from
// the sentinel's own trusted vantage point to check liveness, the same
// rationale as selfCheckProxyPath's certificate skip.
//
// A 502 is treated as unreachable. That's the exact failure #1872
// documented: the sentinel's SNI router successfully dials the tunnel and
// reaches a real HTTP server, but that server (the primary's own Caddy)
// has no route configured for this hostname and answers with Caddy's own
// upstream-unavailable page. A registered-but-502ing hostname is worse
// than a registered-but-unreachable one, because it looks alive in
// GET /sentinel/primaries — that false confidence is what this probe
// exists to remove.
func probeHostname(dial func(spotID string, port int) (net.Conn, error), spotID string, port int, hostname string, timeout time.Duration) AliasHealth {
	health := AliasHealth{Hostname: hostname, CheckedAt: time.Now()}

	conn, err := dialWithTimeout(dial, spotID, port, timeout)
	if err != nil {
		health.Error = fmt.Sprintf("dial: %v", err)
		return health
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, // #nosec G402 -- liveness probe, see doc comment above
	})
	if err := tlsConn.Handshake(); err != nil {
		health.Error = fmt.Sprintf("tls handshake: %v", err)
		return health
	}

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: containarium-sentinel-reachability\r\nConnection: close\r\n\r\n", hostname)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		health.Error = fmt.Sprintf("write request: %v", err)
		return health
	}

	statusLine, err := bufio.NewReader(tlsConn).ReadString('\n')
	if err != nil {
		health.Error = fmt.Sprintf("read response: %v", err)
		return health
	}
	code, err := parseHTTPStatusCode(statusLine)
	if err != nil {
		health.Error = fmt.Sprintf("parse status line %q: %v", strings.TrimSpace(statusLine), err)
		return health
	}
	if code == http.StatusBadGateway {
		health.Error = fmt.Sprintf("upstream returned 502 for %q — the primary's own Caddy has no route for this hostname", hostname)
		return health
	}

	health.Reachable = true
	return health
}

// parseHTTPStatusCode extracts the numeric status code from an HTTP status
// line, e.g. "HTTP/1.1 502 Bad Gateway" -> 502.
func parseHTTPStatusCode(statusLine string) (int, error) {
	parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(parts) < 2 {
		return 0, fmt.Errorf("malformed status line %q", statusLine)
	}
	return strconv.Atoi(parts[1])
}

// checkTunnelPrimaries probes every tunnel-promoted primary's Hostname and
// Aliases end-to-end, dialing through the SAME path buildSNIRoutingHandler
// uses (tunnelRegistry.DialTunnel) rather than trusting registration
// alone, and records the result via PrimaryRegistry.SetAliasHealth so it's
// visible through GET /sentinel/primaries. Logs once per hostname on a
// reachable→unreachable transition, rather than every sweep, so a wedged
// alias is noticed without spamming the log on every tick (#1872).
//
// In-VPC primaries (BackendID empty) are skipped: they're routed via
// Caddy's layer4/routes table, a completely separate mechanism this probe
// doesn't exercise.
func (m *Manager) checkTunnelPrimaries(ctx context.Context) {
	dial := m.reachabilityDial
	if dial == nil && m.tunnelRegistry != nil {
		dial = m.tunnelRegistry.DialTunnel
	}
	if dial == nil {
		return
	}

	for _, p := range m.primaries.All() {
		if p.BackendID == "" {
			continue
		}
		select {
		case <-ctx.Done():
			return
		default:
		}

		spotID := strings.TrimPrefix(p.BackendID, "tunnel-")
		hostnames := append([]string{p.Hostname}, p.Aliases...)
		results := make([]AliasHealth, 0, len(hostnames))
		for _, h := range hostnames {
			if h == "" {
				continue
			}
			result := probeHostname(dial, spotID, p.Port, h, defaultReachabilityTimeout)
			if !result.Reachable && wasReachable(p, h) {
				log.Printf("[sentinel] primary reachability: pool=%q hostname=%q became UNREACHABLE: %s", p.Pool, h, result.Error)
			}
			results = append(results, result)
		}
		m.primaries.SetAliasHealth(p.Pool, p.rev, results)
	}
}

// wasReachable reports whether hostname's previous probe on primary p (if
// any) was reachable. Used only to log reachable→unreachable TRANSITIONS
// instead of re-logging an already-known-bad hostname on every sweep. A
// hostname with no prior result is treated as "was fine" so its first-ever
// failure still logs once.
func wasReachable(p *Primary, hostname string) bool {
	for _, h := range p.AliasHealth {
		if h.Hostname == hostname {
			return h.Reachable
		}
	}
	return true
}

// runPrimaryReachabilityLoop periodically probes every tunnel-promoted
// primary's Hostname/Aliases end-to-end (checkTunnelPrimaries). No-op when
// tunnels aren't in use (m.tunnelRegistry == nil) — there's nothing to
// probe.
func (m *Manager) runPrimaryReachabilityLoop(ctx context.Context) {
	if m.tunnelRegistry == nil {
		return
	}
	interval := m.config.PrimaryReachabilityInterval
	if interval <= 0 {
		interval = defaultReachabilityInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkTunnelPrimaries(ctx)
		}
	}
}
