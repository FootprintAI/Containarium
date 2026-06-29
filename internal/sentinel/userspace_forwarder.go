package sentinel

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// userspaceForwarder is a TCP proxy that runs on the sentinel host,
// listening on a small set of ports and forwarding each accepted
// connection to a fixed backend with an optional PROXY v2 header
// prepended. It exists for the "simple proxy" sentinel mode (single
// GCP spot VM behind the sentinel) — in that mode the legacy code
// path uses kernel iptables DNAT, which cannot inject a PROXY v2
// header because there is no userspace process in the hot path. With
// PROXY v2 missing, the downstream Caddy sees the connection peer as
// the sentinel-NAT'd address (a bridge gateway or sentinel IP, not
// the real client), so visitor-IP-dependent features (logs, audit,
// XFF-aware app code) all see the wrong IP.
//
// This forwarder is only activated when --proxy-protocol is set AND
// the sentinel is NOT already running the multiplexed ConnMux path
// (the multi-pool / tunnel-promoted-primary mode, which has its own
// PROXY v2 emit via buildSNIRoutingHandler). The two paths are
// mutually exclusive so we don't double-listen on :443.
type userspaceForwarder struct {
	mu        sync.Mutex
	listeners []net.Listener
	dialer    *net.Dialer
	emitProxy bool
}

// newUserspaceForwarder constructs an idle forwarder. Call start()
// once with the backend address and ports to serve.
func newUserspaceForwarder(emitProxyV2 bool) *userspaceForwarder {
	return &userspaceForwarder{
		// KeepAlive detects dead backend connections (e.g. a same-IP hard
		// reboot where the kernel resets the TCP stack without sending RSTs).
		// Without it, stale io.Copy goroutine pairs accumulate without bound
		// and can exhaust the sentinel's FDs / goroutines (#769).
		dialer:    &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second},
		emitProxy: emitProxyV2,
	}
}

// start binds listeners on each port and begins serving. Each
// accepted connection dials backend:port (the same port — this is a
// dumb port-for-port forwarder, not a port-remapping proxy), and if
// emitProxy is true, prepends a PROXY v2 frame before the first byte
// of payload. Repeat calls to start() append to the listener set; the
// caller is responsible for calling stop() in between if reconfiguring.
//
// Returns an error if any port fails to bind — but it does NOT roll
// back successfully-bound listeners on partial failure. The caller
// should treat partial-success as an error and stop() everything.
func (f *userspaceForwarder) start(backendIP string, ports []int) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, port := range ports {
		listenAddr := fmt.Sprintf(":%d", port)
		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", listenAddr, err)
		}
		target := fmt.Sprintf("%s:%d", backendIP, port)
		f.listeners = append(f.listeners, ln)
		go f.serve(ln, target)
		log.Printf("[sentinel] userspace forwarder listening on %s -> %s (proxy_v2=%v)",
			listenAddr, target, f.emitProxy)
	}
	return nil
}

// stop closes every listener owned by this forwarder. In-flight
// goroutines copying bytes will see Accept errors / read errors on
// the closed listener and exit. Per-connection goroutines spawned by
// serve() will continue until both io.Copy directions complete or one
// side hangs up — that's intentional: stop() is for shutdown, not for
// reaping live connections.
func (f *userspaceForwarder) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ln := range f.listeners {
		_ = ln.Close()
	}
	f.listeners = nil
}

func (f *userspaceForwarder) serve(ln net.Listener, target string) {
	for {
		client, err := ln.Accept()
		if err != nil {
			// Closed listener (during stop()) or transient accept error.
			// In either case there's no useful retry — exit the goroutine.
			return
		}
		go f.handle(client, target)
	}
}

func (f *userspaceForwarder) handle(client net.Conn, target string) {
	defer func() { _ = client.Close() }()

	upstream, err := f.dialer.Dial("tcp", target)
	if err != nil {
		log.Printf("[sentinel] userspace forwarder: dial %s failed: %v", target, err)
		return
	}
	defer func() { _ = upstream.Close() }()

	// Prepend PROXY v2 frame BEFORE any payload bytes so the
	// downstream peer's PROXY-aware parser reads it as the first
	// thing on the wire. writeProxyHeader extracts the source from
	// the client connection's RemoteAddr — that's the real client IP.
	if f.emitProxy {
		if err := writeProxyHeader(upstream, client); err != nil {
			log.Printf("[sentinel] userspace forwarder: proxy-proto write to %s failed: %v", target, err)
			return
		}
	}

	// Bidirectional copy. Either direction's EOF tears the pair down.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}
