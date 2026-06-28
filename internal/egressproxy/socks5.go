package egressproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// ServeSOCKS5 runs a minimal no-auth SOCKS5 CONNECT proxy on listenAddr until
// ctx is cancelled. It egresses from whatever host runs it — used by the
// operator side of "egress via client" (#808): the box's traffic, tunnelled to
// here, leaves with this machine's IP. Returns the bound address (useful when
// listenAddr used port 0).
//
// Scope is intentionally small: no auth, CONNECT only, IPv4 + domain targets —
// enough for an HTTP(S) browser. It is meant to be bound to loopback and
// exposed to the box exclusively through the authenticated ssh -R tunnel.
func ServeSOCKS5(ctx context.Context, listenAddr string, logf func(string, ...any)) (string, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", fmt.Errorf("socks listen %s: %w", listenAddr, err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go socksHandle(c)
		}
	}()
	logf("socks5 listening on %s", ln.Addr())
	return ln.Addr().String(), nil
}

func socksHandle(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	// Greeting: VER, NMETHODS, METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, int(hdr[1]))); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // no-auth
		return
	}

	// Request: VER, CMD, RSV, ATYP
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != 0x05 {
		return
	}
	if req[1] != 0x01 { // CONNECT only
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		d := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, d); err != nil {
			return
		}
		host = string(d)
	default: // IPv6 unsupported
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)

	up, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 15*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // conn refused
		return
	}
	defer func() { _ = up.Close() }()
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{}) // clear handshake deadline for the data phase

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}
