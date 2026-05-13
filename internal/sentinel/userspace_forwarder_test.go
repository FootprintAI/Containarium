package sentinel

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// (freePort lives in tunnel_test.go and is shared across the package.)

// TestUserspaceForwarder_HandlerWritesProxyFrame is the focused unit
// test: it calls handle() directly with a pre-built client conn pair
// and a mock target backend, bypassing the listener / port-for-port
// constraint. This is what actually matters — that handle() prepends
// the frame when emitProxy=true and not otherwise.
func TestUserspaceForwarder_HandlerWritesProxyFrame(t *testing.T) {
	// Backend listener — independent port, no conflict.
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()

	type fromBackend struct {
		gotHeader bool
		body      []byte
		err       error
	}
	out := make(chan fromBackend, 1)
	go func() {
		c, err := backendLn.Accept()
		if err != nil {
			out <- fromBackend{err: err}
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))

		// Peek the first 12 bytes — PROXY v2 signature is
		// 0x0D 0x0A 0x0D 0x0A 0x00 0x0D 0x0A 0x51 0x55 0x49 0x54 0x0A
		sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
		first := make([]byte, len(sig))
		if _, err := io.ReadFull(c, first); err != nil {
			out <- fromBackend{err: err}
			return
		}
		gotHeader := bytes.Equal(first, sig)
		if gotHeader {
			// drain the rest of the header — 4 fixed bytes + 2-byte length + payload-addrs
			rest := make([]byte, 4)
			if _, err := io.ReadFull(c, rest); err != nil {
				out <- fromBackend{err: err}
				return
			}
			addrLen := int(rest[2])<<8 | int(rest[3])
			addrBuf := make([]byte, addrLen)
			if _, err := io.ReadFull(c, addrBuf); err != nil {
				out <- fromBackend{err: err}
				return
			}
		}
		body, _ := io.ReadAll(c)
		out <- fromBackend{gotHeader: gotHeader, body: body}
	}()

	// Simulate a client conn by dialing the forwarder's "handle"
	// directly. Easiest: use net.Pipe? No — net.Pipe doesn't have
	// a TCP RemoteAddr / LocalAddr that writeProxyHeader needs.
	// Instead, open a real TCP pair via a transient listener.
	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientLn.Close()

	clientConnCh := make(chan net.Conn, 1)
	go func() {
		c, _ := clientLn.Accept()
		clientConnCh <- c
	}()
	clientDial, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientDial.Close()
	clientAccepted := <-clientConnCh
	defer clientAccepted.Close()

	// Write some payload from "client" side so the forwarder has
	// something to copy through.
	go func() {
		_, _ = clientDial.Write([]byte("hello"))
		_ = clientDial.(*net.TCPConn).CloseWrite()
	}()

	// Run handle() with emit=true.
	fwd := newUserspaceForwarder(true)
	fwd.handle(clientAccepted, backendAddr)

	r := <-out
	if r.err != nil {
		t.Fatalf("backend read err: %v", r.err)
	}
	if !r.gotHeader {
		t.Errorf("expected PROXY v2 signature on the wire, didn't see it")
	}
	if string(r.body) != "hello" {
		t.Errorf("payload not forwarded verbatim: got %q want %q", r.body, "hello")
	}
}

// TestUserspaceForwarder_HandlerWritesNoFrameWhenDisabled is the
// counterpart: emit=false means the wire has no PROXY frame, just
// the payload.
func TestUserspaceForwarder_HandlerWritesNoFrameWhenDisabled(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backendLn.Close()

	out := make(chan []byte, 1)
	go func() {
		c, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		body, _ := io.ReadAll(c)
		out <- body
	}()

	clientLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer clientLn.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := clientLn.Accept(); ch <- c }()
	cd, _ := net.Dial("tcp", clientLn.Addr().String())
	defer cd.Close()
	ca := <-ch
	defer ca.Close()
	go func() {
		_, _ = cd.Write([]byte("plain"))
		_ = cd.(*net.TCPConn).CloseWrite()
	}()

	fwd := newUserspaceForwarder(false)
	fwd.handle(ca, backendLn.Addr().String())

	got := <-out
	if string(got) != "plain" {
		t.Errorf("payload not forwarded verbatim: got %q want %q", got, "plain")
	}
	// Make sure the signature is NOT at the start.
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	if bytes.HasPrefix(got, sig) {
		t.Error("PROXY v2 frame was emitted even though emitProxy=false")
	}
}

// TestUserspaceForwarder_StartStopIsIdempotent makes sure stop() can
// be called multiple times and on an empty forwarder without panicking,
// since switchToMaintenance may call it before start() has run on the
// first proxy switch.
func TestUserspaceForwarder_StartStopIsIdempotent(t *testing.T) {
	fwd := newUserspaceForwarder(true)
	fwd.stop() // never started — must not panic

	// Try starting then double-stopping.
	port := freePort(t)
	if err := fwd.start("127.0.0.1", []int{port}); err != nil {
		t.Fatalf("start: %v", err)
	}
	fwd.stop()
	fwd.stop()
}

// TestUserspaceForwarder_BindFailureReturnsError verifies that a port
// conflict surfaces as an error (so switchToProxy can roll back rather
// than continue into a half-configured state). The forwarder binds
// to ":<port>" (all interfaces), so the held listener must do the same
// — on macOS, holding 127.0.0.1:<port> doesn't prevent 0.0.0.0:<port>
// from binding.
func TestUserspaceForwarder_BindFailureReturnsError(t *testing.T) {
	hold, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("hold listen: %v", err)
	}
	defer hold.Close()
	port := hold.Addr().(*net.TCPAddr).Port

	fwd := newUserspaceForwarder(true)
	defer fwd.stop()
	err = fwd.start("127.0.0.1", []int{port})
	if err == nil {
		t.Fatal("expected start() to fail when port is already taken")
	}
	if !strings.Contains(err.Error(), "listen") {
		t.Errorf("error should mention listen failure, got: %v", err)
	}
}
