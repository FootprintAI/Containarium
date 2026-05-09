package sentinel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// proxyV2Sig is the 12-byte PROXY protocol v2 signature.
//
//	\r\n\r\n\x00\r\nQUIT\n
var proxyV2Sig = [12]byte{
	0x0D, 0x0A, 0x0D, 0x0A,
	0x00, 0x0D, 0x0A, 0x51,
	0x55, 0x49, 0x54, 0x0A,
}

// WriteProxyV2 emits a PROXY protocol v2 header describing a TCP connection
// from src to dst. It is intended to be written to the upstream side of a
// TLS-passthrough proxy *before* any application bytes, so the downstream
// parser (e.g. Caddy's proxy_protocol listener wrapper) can recover the real
// client address.
//
// IPv4 produces a 28-byte frame, IPv6 a 52-byte frame. If src and dst are not
// the same family, the call falls back to encoding both as IPv6
// (IPv4-mapped) — this matches what most parsers expect.
//
// Wire format (16-byte fixed header followed by addrs+ports):
//
//	signature       (12)
//	ver+cmd         (1)   = 0x21  (v2, PROXY command)
//	fam+proto       (1)   = 0x11 IPv4/STREAM, 0x21 IPv6/STREAM
//	body length     (2)   = big-endian
//	src addr        (4 or 16)
//	dst addr        (4 or 16)
//	src port        (2)   = big-endian
//	dst port        (2)   = big-endian
func WriteProxyV2(w io.Writer, src, dst *net.TCPAddr) (int, error) {
	if src == nil || dst == nil {
		return 0, fmt.Errorf("proxyproto: nil addr (src=%v dst=%v)", src, dst)
	}

	srcIP4, dstIP4 := src.IP.To4(), dst.IP.To4()
	useV4 := srcIP4 != nil && dstIP4 != nil

	var frame []byte
	if useV4 {
		frame = make([]byte, 16+12)
		copy(frame[16:20], srcIP4)
		copy(frame[20:24], dstIP4)
		binary.BigEndian.PutUint16(frame[24:26], uint16(src.Port))
		binary.BigEndian.PutUint16(frame[26:28], uint16(dst.Port))
		frame[13] = 0x11 // AF_INET + STREAM
		binary.BigEndian.PutUint16(frame[14:16], 12)
	} else {
		frame = make([]byte, 16+36)
		copy(frame[16:32], src.IP.To16())
		copy(frame[32:48], dst.IP.To16())
		binary.BigEndian.PutUint16(frame[48:50], uint16(src.Port))
		binary.BigEndian.PutUint16(frame[50:52], uint16(dst.Port))
		frame[13] = 0x21 // AF_INET6 + STREAM
		binary.BigEndian.PutUint16(frame[14:16], 36)
	}
	copy(frame[0:12], proxyV2Sig[:])
	frame[12] = 0x21 // version 2 + PROXY command

	return w.Write(frame)
}
