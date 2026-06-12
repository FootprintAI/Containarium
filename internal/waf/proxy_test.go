package waf

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// echoServer accepts one connection and echoes lines back, so a test can prove
// bytes flowed client→proxy→upstream→proxy→client.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // echo
			}(c)
		}
	}()
	return ln
}

// TestTransparentProxy_ForwardPath proves the steer→recover→forward→pipe path
// without a real transparent listener: OrigDst is overridden to point every
// accepted connection at the echo server (standing in for the original dst the
// kernel would set via IP_TRANSPARENT), and the proxy must forward bytes and
// pipe the echo back.
func TestTransparentProxy_ForwardPath(t *testing.T) {
	echo := echoServer(t)
	defer echo.Close()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer proxyLn.Close()

	var (
		mu       sync.Mutex
		forwards []string
	)
	p := &TransparentProxy{
		// Stand in for IP_TRANSPARENT's "LocalAddr == original dst".
		OrigDst: func(net.Conn) string { return echo.Addr().String() },
		OnForward: func(orig string) {
			mu.Lock()
			forwards = append(forwards, orig)
			mu.Unlock()
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Serve(ctx, proxyLn) }()

	conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello-waf\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read echo back through proxy: %v", err)
	}
	if line != "hello-waf\n" {
		t.Fatalf("echo mismatch: %q", line)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(forwards) != 1 || forwards[0] != echo.Addr().String() {
		t.Fatalf("OnForward = %v, want one entry for the original dst %s", forwards, echo.Addr())
	}
}

// TestTransparentProxy_DialFailureClosesClient ensures a connection whose
// original dst is unreachable is closed promptly rather than hanging.
func TestTransparentProxy_DialFailureClosesClient(t *testing.T) {
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer proxyLn.Close()

	p := &TransparentProxy{
		// A dialer that always fails (stands in for a dead upstream).
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Err: io.EOF}
		},
		OrigDst:     func(net.Conn) string { return "10.255.255.1:9" },
		DialTimeout: time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Serve(ctx, proxyLn) }()

	conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// The proxy should close our side once the upstream dial fails: a read returns
	// EOF promptly (well within the deadline).
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != io.EOF {
		t.Fatalf("expected EOF after upstream dial failure, got %v", err)
	}
}

func TestListenAddrValid(t *testing.T) {
	for _, ok := range []string{":15001", "127.0.0.1:15001", "0.0.0.0:8080"} {
		if !ListenAddrValid(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "noport", "15001"} {
		if ListenAddrValid(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

// TestNewTransparentListener_NonLinux documents that off-Linux the bind errors
// (the proxy logic above is still tested cross-platform via injection).
func TestNewTransparentListener_NonLinux(t *testing.T) {
	if isLinux() {
		t.Skip("Linux: NewTransparentListener binds for real (covered by the backend runbook)")
	}
	if _, err := NewTransparentListener(":0"); err == nil {
		t.Error("expected an error binding a transparent listener off-Linux")
	}
}
