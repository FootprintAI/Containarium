package sentinel

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TestHandleStreamHonorsForward verifies a Forward entry overrides the
// default 127.0.0.1:port dial: a stream for the mapped port reaches the
// custom target (a local listener on a different port), proving the K8s
// gateway-dial override works.
func TestHandleStreamHonorsForward(t *testing.T) {
	// Target listener stands in for the in-cluster gateway address.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer func() { _ = target.Close() }()

	got := make(chan string, 1)
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 5)
		_, _ = io.ReadFull(c, buf)
		got <- string(buf)
	}()

	// Advertised port 32022 forwards to the target listener's real address.
	tc := &TunnelClient{Forward: map[int]string{32022: target.Addr().String()}}

	// A pipe stands in for the yamux stream: write the 2-byte port header +
	// payload, then handleStream should relay it to the target.
	clientEnd, streamEnd := net.Pipe()
	go tc.handleStream(streamEnd)

	hdr := make([]byte, 2)
	binary.BigEndian.PutUint16(hdr, 32022)
	if _, err := clientEnd.Write(hdr); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := clientEnd.Write([]byte("hello")); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	select {
	case s := <-got:
		if s != "hello" {
			t.Errorf("target received %q, want hello", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("payload never reached the forwarded target")
	}
	_ = clientEnd.Close()
}
