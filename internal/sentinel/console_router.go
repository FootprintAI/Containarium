package sentinel

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// ConsoleRouterPolicy authorizes a caller to route through the console
// router to any registered spot's advertised port. Deliberately
// coarse-grained — one shared secret, not a per-spot ACL — because the
// real per-guest authorization happens one hop downstream, at the
// hypervisor-agent's own token + target check
// (internal/hypervisor.Agent.HandleConn). This layer only gates "can this
// caller reach the tunnel infrastructure for console routing at all",
// matching the tunnel's own legacy single-token shape (see PolicyFromCLI)
// rather than inventing a second fine-grained credential system.
type ConsoleRouterPolicy struct {
	token string
}

// NewConsoleRouterPolicy returns a policy that authorizes exactly one
// shared token. An empty token authorizes nothing — Validate always fails
// on an unconfigured policy rather than treating "no token configured" as
// "any token is fine".
func NewConsoleRouterPolicy(token string) *ConsoleRouterPolicy {
	return &ConsoleRouterPolicy{token: token}
}

// Validate reports whether presented matches the configured token.
func (p *ConsoleRouterPolicy) Validate(presented string) error {
	if p.token == "" || presented == "" {
		return fmt.Errorf("invalid token")
	}
	if subtle.ConstantTimeCompare([]byte(p.token), []byte(presented)) != 1 {
		return fmt.Errorf("invalid token")
	}
	return nil
}

// ConsoleRouterHandshake is the single JSON line a caller sends immediately
// after connecting, before the connection becomes a raw relay. SpotID and
// Port identify which hypervisor-agent (or, in principle, any tunnel
// backend) to reach — the router itself is agnostic to what is actually
// listening on that port, exactly like the existing tunnel port-forward
// path.
type ConsoleRouterHandshake struct {
	Token  string `json:"token"`
	SpotID string `json:"spot_id"`
	Port   int    `json:"port"`
}

// ConsoleRouterResponse is the single JSON line the router sends back
// before either closing (on failure) or turning into a raw relay (on
// success).
type ConsoleRouterResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ConsoleRouter makes any port a connected tunnel spot advertises publicly
// reachable through the sentinel, gated by ConsoleRouterPolicy. It is a
// sibling to sshpiper (:22, routed by username) and the SNI router (:443,
// routed by hostname) — those are this codebase's only two existing public
// routes into the tunnel; nothing previously exposed an arbitrary
// advertised port. See docs/architecture/byoc-vm-console-access.md.
type ConsoleRouter struct {
	listenAddr string
	policy     *ConsoleRouterPolicy
	registry   *TunnelRegistry
}

// NewConsoleRouter returns a ConsoleRouter. registry is the same
// TunnelRegistry the TunnelServer populates — DialTunnel is the only
// registry method this needs.
func NewConsoleRouter(listenAddr string, policy *ConsoleRouterPolicy, registry *TunnelRegistry) *ConsoleRouter {
	return &ConsoleRouter{listenAddr: listenAddr, policy: policy, registry: registry}
}

// Run starts the console router on its own port. Blocks until ctx is
// cancelled.
func (cr *ConsoleRouter) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", cr.listenAddr)
	if err != nil {
		return fmt.Errorf("console router listen on %s: %w", cr.listenAddr, err)
	}
	defer func() { _ = ln.Close() }()

	log.Printf("[console-router] listening on %s", cr.listenAddr)
	return cr.Serve(ctx, ln)
}

// Serve accepts connections from the given listener. Use this when the
// listener is provided externally (e.g., from a ConnMux), mirroring
// TunnelServer.Serve. Blocks until ctx is cancelled or the listener closes.
func (cr *ConsoleRouter) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				if isClosedErr(err) {
					return nil
				}
				log.Printf("[console-router] accept error: %v", err)
				continue
			}
		}
		go cr.handleConnection(conn)
	}
}

func (cr *ConsoleRouter) handleConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	remoteAddr := conn.RemoteAddr().String()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var hs ConsoleRouterHandshake
	if err := readHandshakeLine(conn, &hs); err != nil {
		log.Printf("[console-router] handshake read error from %s: %v", remoteAddr, err)
		return
	}

	if err := cr.policy.Validate(hs.Token); err != nil {
		log.Printf("[console-router] rejecting %s: %v", remoteAddr, err)
		cr.reject(conn, "unauthorized")
		return
	}
	if hs.SpotID == "" {
		cr.reject(conn, "spot_id is required")
		return
	}
	if hs.Port <= 0 || hs.Port > 65535 {
		cr.reject(conn, "a valid port is required")
		return
	}

	stream, err := cr.registry.DialTunnel(hs.SpotID, hs.Port)
	if err != nil {
		log.Printf("[console-router] dial failed for %s (spot=%q port=%d): %v", remoteAddr, hs.SpotID, hs.Port, err)
		cr.reject(conn, err.Error())
		return
	}
	defer func() { _ = stream.Close() }()

	_ = conn.SetDeadline(time.Time{})
	if err := json.NewEncoder(conn).Encode(ConsoleRouterResponse{OK: true}); err != nil {
		return
	}

	log.Printf("[console-router] routing %s to spot=%q port=%d", remoteAddr, hs.SpotID, hs.Port)
	relayConsole(conn, stream)
}

func (cr *ConsoleRouter) reject(conn net.Conn, reason string) {
	_ = json.NewEncoder(conn).Encode(ConsoleRouterResponse{OK: false, Error: reason})
}

// relayConsole bidirectionally copies bytes between a and b until either
// side's copy finishes, then returns. Matches the tunnel client's own
// bidirectional-copy shape (internal/sentinel/tunnel_client.go); named
// distinctly from any helper in this file's neighbors since it is a
// package-level function other sentinel code may already shadow.
func relayConsole(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}
