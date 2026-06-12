package waf

import (
	"context"
	"fmt"
	"log"
	"net"
)

// Config configures the steering proxy. Addr is required; the rest is the PR-2
// inspection layer (nil Inspector → PR-1 forward-only behavior).
type Config struct {
	Addr         string
	Inspector    Inspector                                  // nil → forward-only
	EnforceBlock bool                                       // false → observe+audit, don't 403
	OnBlock      func(orig string, v Verdict, dropped bool) // audit hook
}

// Start binds a transparent listener and serves the steering proxy in a
// background goroutine until ctx is cancelled. Returns an error if the listener
// can't be bound (e.g. not Linux, or missing CAP_NET_ADMIN); the caller logs and
// continues without WAF steering.
func Start(ctx context.Context, cfg Config) error {
	ln, err := NewTransparentListener(cfg.Addr)
	if err != nil {
		return fmt.Errorf("waf: bind transparent listener on %s: %w", cfg.Addr, err)
	}
	p := &TransparentProxy{
		Inspector:    cfg.Inspector,
		EnforceBlock: cfg.EnforceBlock,
		OnBlock:      cfg.OnBlock,
		OnForward:    func(orig string) { log.Printf("[waf] steered connection → original dst %s", orig) },
	}
	mode := "forward-only (no inspection)"
	if cfg.Inspector != nil {
		if cfg.EnforceBlock {
			mode = "inspecting (ENFORCE — blocks on a match)"
		} else {
			mode = "inspecting (observe-only — audits, does not block)"
		}
	}
	log.Printf("[waf] transparent steering proxy listening on %s: %s (apply the nft TPROXY rule to steer — see the runbook)", cfg.Addr, mode)
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
