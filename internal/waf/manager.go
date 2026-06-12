package waf

import (
	"context"
	"fmt"
	"log"
	"net"
)

// Start binds a transparent listener on addr and serves the steering proxy in a
// background goroutine until ctx is cancelled. Returns an error if the listener
// can't be bound (e.g. not Linux, or missing CAP_NET_ADMIN); the caller logs and
// continues without WAF steering. PR-1: forwards only, no inspection.
func Start(ctx context.Context, addr string) error {
	ln, err := NewTransparentListener(addr)
	if err != nil {
		return fmt.Errorf("waf: bind transparent listener on %s: %w", addr, err)
	}
	p := &TransparentProxy{
		OnForward: func(orig string) {
			log.Printf("[waf] steered connection → original dst %s (forward-only, PR-1)", orig)
		},
	}
	log.Printf("[waf] transparent steering proxy listening on %s (forward-only; apply the nft TPROXY rule to steer — see the PR-1 runbook)", addr)
	go func() {
		if err := p.Serve(ctx, ln); err != nil {
			log.Printf("[waf] proxy serve stopped: %v", err)
		}
	}()
	return nil
}

// ListenAddrValid reports whether addr is a usable host:port for the proxy, so
// the daemon can reject a malformed CONTAINARIUM_WAF_TPROXY_ADDR early with a
// clear message instead of a late bind failure.
func ListenAddrValid(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}
