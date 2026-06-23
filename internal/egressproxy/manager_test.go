package egressproxy

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestManager_StartStop_AndForward: the manager starts a relay (port 0 ->
// discovers the bound addr), forwards an allowed source to the upstream, and
// Stop tears it down so the port is released.
func TestManager_StartStop_AndForward(t *testing.T) {
	// Echo upstream.
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream: %v", err)
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

	m := NewManager()
	addr, err := m.Start("box-1", "127.0.0.1:0", up.Addr().String(), []string{"127.0.0.1/8"}, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if addr == "" {
		t.Fatal("Start returned empty addr")
	}
	if m.Active() != 1 {
		t.Fatalf("Active = %d, want 1", m.Active())
	}

	// Forward works through the manager-started relay.
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte("hi"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hi" {
		t.Fatalf("echo through relay: got %q err %v", buf, err)
	}
	_ = c.Close()

	// Stop releases the port.
	if !m.Stop("box-1") {
		t.Fatal("Stop reported no relay")
	}
	if m.Active() != 0 {
		t.Fatalf("Active after stop = %d, want 0", m.Active())
	}
	// Stop again is a no-op.
	if m.Stop("box-1") {
		t.Fatal("second Stop should report false")
	}
}

// TestManager_StartReplacesExisting: re-Start for the same key tears down the
// prior relay rather than leaking it.
func TestManager_StartReplacesExisting(t *testing.T) {
	m := NewManager()
	if _, err := m.Start("box", "127.0.0.1:0", "127.0.0.1:1", []string{"127.0.0.1/8"}, nil); err != nil {
		t.Fatalf("start 1: %v", err)
	}
	if _, err := m.Start("box", "127.0.0.1:0", "127.0.0.1:1", []string{"127.0.0.1/8"}, nil); err != nil {
		t.Fatalf("start 2: %v", err)
	}
	if m.Active() != 1 {
		t.Fatalf("Active = %d, want 1 (replace, not leak)", m.Active())
	}
}
