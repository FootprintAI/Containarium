package server

import (
	"bytes"
	"errors"
	"log"
	"os"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func capturePeerLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func TestPeerTransport_Value(t *testing.T) {
	plain := NewPeerPool("b1", "", nil, "")
	secured := NewPeerPool("b1", "", nil, "")
	secured.pki = &peerPKI{}

	tests := []struct {
		name string
		pool *PeerPool
		want pb.PeerTransport
	}{
		{"no pool", nil, pb.PeerTransport_PEER_TRANSPORT_UNSPECIFIED},
		{"no peer pki", plain, pb.PeerTransport_PEER_TRANSPORT_HTTP},
		{"peer pki bootstrapped", secured, pb.PeerTransport_PEER_TRANSPORT_MTLS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := peerTransportOf(tt.pool); got != tt.want {
				t.Fatalf("peerTransportOf = %v, want %v", got, tt.want)
			}
		})
	}
	if secured.PeerMTLSEnabled() != true || plain.PeerMTLSEnabled() != false {
		t.Fatalf("PeerMTLSEnabled mismatch")
	}
}

func TestPeerPool_LogPlainHTTPOnce(t *testing.T) {
	buf := capturePeerLog(t)
	p := NewPeerPool("b1", "", nil, "")
	err := errors.New("peer CA not configured on this sentinel")

	p.LogPlainHTTPOnce(err)
	p.LogPlainHTTPOnce(err)
	p.LogPlainHTTPOnce(nil)

	out := buf.String()
	if n := strings.Count(out, "peer mTLS not enabled"); n != 1 {
		t.Fatalf("want exactly 1 log line, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "plain HTTP") {
		t.Fatalf("log must state the consequence (plain HTTP): %s", out)
	}
	if strings.Contains(out, "bootstrap failed") {
		t.Fatalf("log must not read as a fault: %s", out)
	}
	if !strings.Contains(out, "peer CA not configured") {
		t.Fatalf("log should keep the reason: %s", out)
	}
}

func TestPeerPool_LogPlainHTTPOnce_SkippedWhenMTLS(t *testing.T) {
	buf := capturePeerLog(t)
	p := NewPeerPool("b1", "", nil, "")
	p.pki = &peerPKI{}
	p.LogPlainHTTPOnce(nil)
	if buf.Len() != 0 {
		t.Fatalf("no log expected when mTLS active, got %q", buf.String())
	}
}
