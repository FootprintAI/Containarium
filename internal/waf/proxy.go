// Package waf is the Tier 3 (#662) userspace-WAF-behind-eBPF-steering slice.
//
// PR-1 (this code) is the steering DE-RISK: a transparent proxy that accepts
// connections steered to it by TPROXY, recovers each one's ORIGINAL destination,
// dials it, and pipes bytes both ways — with NO WAF inspection yet. Its only job
// is to prove the steer→recover→forward path works end to end before the WAF
// engine (Coraza) is embedded in PR-2. See docs/security/VIRTUAL-PATCHING-TIER3.md.
//
// Off by default: the daemon only starts the proxy when CONTAINARIUM_WAF_TPROXY_ADDR
// is set, and steering requires an operator-applied nft TPROXY rule + routing
// (the PR-1 runbook), so an existing deployment is entirely unaffected.
package waf

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// defaultDialTimeout bounds the upstream dial so a steered connection to a dead
// service fails fast rather than hanging the proxy goroutine.
const defaultDialTimeout = 10 * time.Second

// TransparentProxy forwards a TPROXY-steered connection to its original
// destination. It holds no per-connection state beyond the goroutines piping
// bytes, so it is safe for concurrent connections.
type TransparentProxy struct {
	// OrigDst returns a connection's original destination address. With an
	// IP_TRANSPARENT listener the kernel sets the accepted socket's LOCAL address
	// to the original dst (that's the point of TPROXY), so the default simply
	// reads conn.LocalAddr(). Overridable so the forward path is testable without
	// a real transparent listener.
	OrigDst func(net.Conn) string

	// Dialer dials the upstream (original dst). Defaults to a plain net.Dialer; a
	// test injects a fake. The proxy's own dials are locally-originated, so they
	// traverse the OUTPUT path and do NOT re-hit the PREROUTING TPROXY rule —
	// no steering loop. (Documented in the runbook.)
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

	// DialTimeout bounds the upstream dial (0 → defaultDialTimeout).
	DialTimeout time.Duration

	// OnForward, if set, is called once per accepted connection with the recovered
	// original destination — used by the validator/tests to observe steering.
	OnForward func(orig string)

	// Inspector, if set (#662 PR-2), examines the reassembled request head before
	// forwarding. Nil → forward-only (PR-1). When a verdict blocks:
	//   - EnforceBlock true  → write a 403 and DON'T forward.
	//   - EnforceBlock false → forward anyway (observe-only), still calling OnBlock.
	// Mirrors the rest of the stack: audit always, drop only when armed.
	Inspector    Inspector
	EnforceBlock bool

	// OnBlock, if set, is called when the Inspector returns a blocking verdict
	// (whether or not EnforceBlock dropped it), with the original dst and verdict —
	// the daemon wires this to the audit log.
	OnBlock func(orig string, v Verdict, dropped bool)
}

func (p *TransparentProxy) origDst(c net.Conn) string {
	if p.OrigDst != nil {
		return p.OrigDst(c)
	}
	return c.LocalAddr().String()
}

func (p *TransparentProxy) dial(ctx context.Context, addr string) (net.Conn, error) {
	if p.Dialer != nil {
		return p.Dialer(ctx, "tcp", addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

func (p *TransparentProxy) dialTimeout() time.Duration {
	if p.DialTimeout > 0 {
		return p.DialTimeout
	}
	return defaultDialTimeout
}

// Serve accepts connections from ln until the listener is closed (or ctx is
// cancelled) and forwards each. It blocks; run it in a goroutine. A transient
// Accept error is logged and retried; a permanent one (closed listener) returns.
func (p *TransparentProxy) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close() // unblock Accept on shutdown
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // shut down
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go p.handle(ctx, conn)
	}
}

// handle recovers a connection's original destination, dials it, and pipes bytes
// both ways until either side closes.
func (p *TransparentProxy) handle(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()
	orig := p.origDst(client)
	if p.OnForward != nil {
		p.OnForward(orig)
	}

	// PR-2 inspection: read + inspect the reassembled request head before
	// forwarding. The head bytes are replayed verbatim to the upstream after a
	// pass (byte-preserving), so a steered HTTP request is unmodified end to end.
	var head []byte
	if p.Inspector != nil {
		head = readHead(client, maxHeadBytes)
		v := p.Inspector.Inspect(head)
		if v.Block {
			if p.OnBlock != nil {
				p.OnBlock(orig, v, p.EnforceBlock)
			}
			if p.EnforceBlock {
				_, _ = client.Write(block403) // refuse; don't forward the exploit
				return
			}
			// observe-only: fall through and forward, having audited the match.
		}
	}

	dctx, cancel := context.WithTimeout(ctx, p.dialTimeout())
	defer cancel()
	upstream, err := p.dial(dctx, orig)
	if err != nil {
		log.Printf("[waf] steer: dial original dst %s failed: %v", orig, err)
		return
	}
	defer func() { _ = upstream.Close() }()

	// Replay the inspected head to the upstream, then pipe the remainder both ways.
	if len(head) > 0 {
		if _, err := upstream.Write(head); err != nil {
			log.Printf("[waf] steer: replay head to %s failed: %v", orig, err)
			return
		}
	}

	// Bidirectional copy with TCP half-close so an EOF in one direction is
	// propagated (a half-closed client shouldn't tear down the still-active
	// response direction).
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pipe(upstream, client) }() // client → upstream
	go func() { defer wg.Done(); pipe(client, upstream) }() // upstream → client
	wg.Wait()
}

// pipe copies src→dst then half-closes dst's write side (so the peer sees EOF)
// without closing the whole conn, which the other direction may still be using.
func pipe(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
