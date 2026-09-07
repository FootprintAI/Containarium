package hypervisor

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shortTempDir returns a short-path temp directory. Unlike t.TempDir()
// (which embeds the full test name), this stays under the ~104-byte
// sun_path limit UNIX domain sockets have on macOS/BSD.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hv")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// listenFakeConsoleSocket starts a UNIX listener standing in for VirtualBox's
// serial-port redirect and echoes back everything it reads, so a test can
// verify OpenConsole actually reaches the right socket without VirtualBox.
func listenFakeConsoleSocket(t *testing.T, path string) net.Listener {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("failed to listen on fake console socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				_, _ = conn.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	return ln
}

func TestVirtualBoxProvider_OpenConsole_RoundTrips(t *testing.T) {
	dir := shortTempDir(t)
	sockPath := filepath.Join(dir, "containarium-byoc-1.sock")
	listenFakeConsoleSocket(t, sockPath)

	p := NewVirtualBoxProvider(dir)
	conn, err := p.OpenConsole(context.Background(), "containarium-byoc-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("hello console")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	buf := make([]byte, 32)
	_ = conn.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if got := string(buf[:n]); got != "hello console" {
		t.Fatalf("got %q, want echoed %q", got, "hello console")
	}
}

func TestVirtualBoxProvider_OpenConsole_NoSocketForTarget(t *testing.T) {
	dir := shortTempDir(t)
	p := NewVirtualBoxProvider(dir)

	if _, err := p.OpenConsole(context.Background(), "no-such-guest"); err == nil {
		t.Fatal("expected an error dialing a socket that doesn't exist")
	}
}

func TestVirtualBoxProvider_OpenConsole_EmptyTarget(t *testing.T) {
	dir := shortTempDir(t)
	p := NewVirtualBoxProvider(dir)

	if _, err := p.OpenConsole(context.Background(), ""); err == nil {
		t.Fatal("expected an error for an empty target")
	}
}

func TestVirtualBoxProvider_OpenConsole_NoResolverConfigured(t *testing.T) {
	p := &VirtualBoxProvider{}
	if _, err := p.OpenConsole(context.Background(), "containarium-byoc-1"); err == nil {
		t.Fatal("expected an error when SocketPath is unset")
	}
}

func TestVirtualBoxProvider_SocketPathConvention(t *testing.T) {
	p := NewVirtualBoxProvider("/var/lib/containarium/consoles")
	got, err := p.SocketPath("containarium-byoc-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "/var/lib/containarium/consoles/containarium-byoc-2.sock"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

var _ io.ReadWriteCloser = (*net.UnixConn)(nil) // sanity: net.Dial("unix", ...) satisfies our interface
