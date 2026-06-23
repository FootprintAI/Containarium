package egressproxy

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestParseAllow_AndSourceAllowed(t *testing.T) {
	r, err := New("127.0.0.1:0", "127.0.0.1:1", []string{"10.100.0.156", "192.168.0.0/16"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.100.0.156", true},  // exact box IP (/32)
		{"10.100.0.157", false}, // sibling box on the same bridge — must be denied
		{"192.168.5.9", true},   // inside the CIDR
		{"10.0.0.1", false},     // unrelated
	}
	for _, c := range cases {
		got := r.sourceAllowed(mustAddr(t, c.ip))
		if got != c.want {
			t.Errorf("sourceAllowed(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestSourceAllowed_EmptyAllowDeniesAll(t *testing.T) {
	r, err := New("127.0.0.1:0", "127.0.0.1:1", nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if r.sourceAllowed(mustAddr(t, "10.100.0.156")) {
		t.Error("empty allow list must deny everyone (fail-closed)")
	}
}

func TestNew_RejectsBadInput(t *testing.T) {
	if _, err := New("no-port", "127.0.0.1:1", nil, nil); err == nil {
		t.Error("expected error on bad listen")
	}
	if _, err := New("127.0.0.1:1", "no-port", nil, nil); err == nil {
		t.Error("expected error on bad upstream")
	}
	if _, err := New("127.0.0.1:1", "127.0.0.1:2", []string{"not-an-ip"}, nil); err == nil {
		t.Error("expected error on bad allow")
	}
}

// TestRelay_ForwardsAllowedSource: an allowed source's bytes reach the upstream
// and the reply comes back. Loopback (127.0.0.1) is the source, so allow it.
func TestRelay_ForwardsAllowedSource(t *testing.T) {
	// Echo upstream.
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()

	r, err := New("127.0.0.1:0", up.Addr().String(), []string{"127.0.0.1/8"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Bind explicitly so the test knows the relay address.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	r.listen = ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Serve(ctx) }()
	waitListen(t, r.listen)

	c, err := net.DialTimeout("tcp", r.listen, 2*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q, want ping (echo through relay)", buf)
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return a
}

func waitListen(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("relay never came up on %s", addr)
}
