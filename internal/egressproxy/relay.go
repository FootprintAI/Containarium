// Package egressproxy implements the host-side relay for "egress via client"
// (#808, Phase 2a).
//
// A box runs in its own network namespace and can reach the host's bridge
// gateway, but NOT a host-side `ssh -R` listener (host loopback) or, directly,
// an off-box network like the operator's tailnet. The relay bridges the two:
// it binds a bridge-gateway address the box can reach, accepts ONLY the target
// box's source IP (the multi-tenant boundary), and forwards each connection to
// a host-reachable upstream — typically the operator's SOCKS proxy reachable
// from the host (e.g. over Tailscale). The box's apps point at the relay as
// their SOCKS proxy and egress with the operator's IP.
//
// The relay is intentionally protocol-agnostic raw TCP: a SOCKS handshake from
// the box passes straight through to the upstream SOCKS server.
package egressproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Relay is a source-restricted TCP forwarder. The zero value is not usable;
// construct with New.
type Relay struct {
	listen   string
	upstream string
	allow    []netip.Prefix
	logf     func(string, ...any)

	mu sync.Mutex
	ln net.Listener
}

// New builds a relay. listen and upstream are host:port. allow is a list of
// source prefixes (CIDR) or bare IPs (treated as /32 or /128) permitted to use
// the relay; an empty allow list denies everyone (fail-closed). logf may be nil.
func New(listen, upstream string, allow []string, logf func(string, ...any)) (*Relay, error) {
	if _, _, err := net.SplitHostPort(listen); err != nil {
		return nil, fmt.Errorf("invalid --listen %q: %w", listen, err)
	}
	if _, _, err := net.SplitHostPort(upstream); err != nil {
		return nil, fmt.Errorf("invalid --upstream %q: %w", upstream, err)
	}
	prefixes, err := parseAllow(allow)
	if err != nil {
		return nil, err
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Relay{listen: listen, upstream: upstream, allow: prefixes, logf: logf}, nil
}

// parseAllow turns CIDR/bare-IP strings into prefixes. A bare IP becomes a
// host route (/32 or /128).
func parseAllow(allow []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, a := range allow {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if strings.Contains(a, "/") {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				return nil, fmt.Errorf("invalid --allow %q: %w", a, err)
			}
			out = append(out, p)
			continue
		}
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return nil, fmt.Errorf("invalid --allow %q: %w", a, err)
		}
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return out, nil
}

// sourceAllowed reports whether src is permitted. Fail-closed: no prefixes ⇒
// nothing allowed.
func (r *Relay) sourceAllowed(src netip.Addr) bool {
	src = src.Unmap()
	for _, p := range r.allow {
		if p.Contains(src) {
			return true
		}
	}
	return false
}

// Serve binds and forwards until ctx is cancelled or a fatal accept error
// occurs. Close (or ctx cancel) makes it return.
func (r *Relay) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", r.listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", r.listen, err)
	}
	r.mu.Lock()
	r.ln = ln
	r.mu.Unlock()
	return r.serveListener(ctx, ln)
}

// StartBackground binds synchronously — returning any bind error to the caller
// (so a "port in use" surfaces at start time, not silently) — then serves in a
// background goroutine until ctx is cancelled. Use Addr afterwards to read the
// actually-bound address (e.g. when the listen port was 0).
func (r *Relay) StartBackground(ctx context.Context) error {
	ln, err := net.Listen("tcp", r.listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", r.listen, err)
	}
	r.mu.Lock()
	r.ln = ln
	r.mu.Unlock()
	go func() { _ = r.serveListener(ctx, ln) }()
	return nil
}

// Addr returns the actually-bound listen address, or "" if not yet bound.
func (r *Relay) Addr() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ln != nil {
		return r.ln.Addr().String()
	}
	return ""
}

func (r *Relay) serveListener(ctx context.Context, ln net.Listener) error {
	r.logf("egress-relay %s -> %s (allow %v)", ln.Addr(), r.upstream, r.allow)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}
		go r.handle(c)
	}
}

func (r *Relay) handle(c net.Conn) {
	defer c.Close()
	ap, ok := remoteAddrPort(c.RemoteAddr())
	if !ok || !r.sourceAllowed(ap.Addr()) {
		r.logf("egress-relay DENY %s (allow %v)", c.RemoteAddr(), r.allow)
		return
	}
	up, err := net.DialTimeout("tcp", r.upstream, 15*time.Second)
	if err != nil {
		r.logf("egress-relay upstream %s dial failed: %v", r.upstream, err)
		return
	}
	defer up.Close()
	// Bidirectional copy; both directions end when either side closes.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// remoteAddrPort extracts a netip.AddrPort from a net.Addr (TCP).
func remoteAddrPort(a net.Addr) (netip.AddrPort, bool) {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.AddrPort(), true
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return ap, true
}

// Close stops the relay.
func (r *Relay) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ln != nil {
		return r.ln.Close()
	}
	return nil
}
