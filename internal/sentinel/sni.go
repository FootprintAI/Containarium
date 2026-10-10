package sentinel

import (
	"bufio"
	"errors"
	"net"
)

// errNotTLS indicates the connection's first bytes are not a TLS handshake.
var errNotTLS = errors.New("not a TLS handshake")

// errNoSNI indicates a valid TLS handshake without a server_name extension.
var errNoSNI = errors.New("no SNI in ClientHello")

// peekSNI reads enough of a TLS ClientHello from conn to extract SNI without
// consuming the bytes. It returns the SNI hostname and a connection that
// transparently replays the peeked bytes followed by the rest of the original
// connection. The returned net.Conn must be used in place of conn for any
// further reads.
//
// If the peek fails (not TLS, malformed, or no SNI), an error is returned but
// the returned net.Conn is still usable — callers can fall through to a
// non-SNI-based forwarding path.
func peekSNI(conn net.Conn) (string, net.Conn, error) {
	full, wrapped, err := peekHelloRecord(conn)
	if err != nil {
		return "", wrapped, err
	}
	sni, err := extractSNI(full)
	return sni, wrapped, err
}

// clientHello holds the fields the sentinel mux reads from a peeked TLS
// ClientHello.
type clientHello struct {
	// SNI is the server_name host_name value, or "" when the extension is
	// absent.
	SNI string
	// ALPN is the application_layer_protocol_negotiation protocol list in
	// the order offered, or nil when the extension is absent.
	ALPN []string
}

// peekClientHello is like peekSNI but also returns the ALPN protocol list.
// A ClientHello without SNI or ALPN is not an error; the corresponding field
// is simply empty. The returned net.Conn replays the peeked bytes and must be
// used in place of conn, including on error.
func peekClientHello(conn net.Conn) (clientHello, net.Conn, error) {
	full, wrapped, err := peekHelloRecord(conn)
	if err != nil {
		return clientHello{}, wrapped, err
	}
	hello, err := parseClientHello(full)
	return hello, wrapped, err
}

// maxHelloRecord is the largest TLS record the peek helpers buffer:
// 5-byte header plus a 16384-byte body.
const maxHelloRecord = 16389

// peekHelloRecord peeks the first TLS record from conn without consuming it.
func peekHelloRecord(conn net.Conn) ([]byte, net.Conn, error) {
	br := bufio.NewReaderSize(conn, maxHelloRecord)
	wrapped := &peekConn{Conn: conn, r: br}
	full, err := peekHelloRecordFrom(br)
	return full, wrapped, err
}

// peekHelloRecordFrom peeks the first TLS record from br without consuming
// it. br must have been created with at least maxHelloRecord of buffer.
func peekHelloRecordFrom(br *bufio.Reader) ([]byte, error) {
	// Peek the 5-byte record header to learn record length.
	hdr, err := br.Peek(5)
	if err != nil || len(hdr) < 5 {
		return nil, errNotTLS
	}
	if hdr[0] != 0x16 { // TLS handshake content type
		return nil, errNotTLS
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	total := 5 + recLen
	if total < 5 || total > maxHelloRecord {
		return nil, errNotTLS
	}

	full, err := br.Peek(total)
	if err != nil || len(full) < total {
		return nil, errNotTLS
	}
	return full, nil
}

// extractSNI parses a TLS ClientHello (record-framed, starting at byte 0)
// and returns the SNI host_name extension value. It performs strict bounds
// checks at every step so a malformed handshake returns an error rather than
// panicking on slice bounds.
func extractSNI(buf []byte) (string, error) {
	hello, err := parseHello(buf, false)
	return hello.SNI, err
}

// parseClientHello parses the SNI and ALPN extensions of a record-framed
// ClientHello. A malformed extension yields an error; absent extensions do
// not.
func parseClientHello(buf []byte) (clientHello, error) {
	return parseHello(buf, true)
}

// parseHello is the shared ClientHello walker. With withALPN false it keeps
// the original SNI-only contract: it returns as soon as the SNI extension is
// found (ignoring anything after it) and reports errNoSNI when absent. With
// withALPN true it visits every extension and a missing SNI is not an error.
func parseHello(buf []byte, withALPN bool) (clientHello, error) {
	var hello clientHello
	// Record header: type(1) + version(2) + length(2)
	if len(buf) < 5 || buf[0] != 0x16 {
		return hello, errNotTLS
	}
	recLen := int(buf[3])<<8 | int(buf[4])
	if len(buf) < 5+recLen {
		return hello, errors.New("record body truncated")
	}
	body := buf[5 : 5+recLen]

	// Handshake: type(1) + length(3) + body
	if len(body) < 4 || body[0] != 0x01 {
		return hello, errors.New("not a ClientHello")
	}
	p := body[4:]

	// ClientHello: legacy_version(2) + random(32) + session_id_length(1)
	if len(p) < 2+32+1 {
		return hello, errors.New("ClientHello too short")
	}
	p = p[2+32:] // skip version + random

	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen {
		return hello, errors.New("session id truncated")
	}
	p = p[sidLen:]

	if len(p) < 2 {
		return hello, errors.New("no cipher suites length")
	}
	csLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csLen {
		return hello, errors.New("cipher suites truncated")
	}
	p = p[csLen:]

	if len(p) < 1 {
		return hello, errors.New("no compression length")
	}
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen {
		return hello, errors.New("compression methods truncated")
	}
	p = p[cmLen:]

	// Extensions
	if len(p) < 2 {
		if withALPN {
			return hello, nil // no extensions block at all (TLS 1.0 ClientHello)
		}
		return hello, errNoSNI
	}
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extLen {
		return hello, errors.New("extensions truncated")
	}
	exts := p[:extLen]

	for len(exts) >= 4 {
		extType := int(exts[0])<<8 | int(exts[1])
		extDataLen := int(exts[2])<<8 | int(exts[3])
		if 4+extDataLen > len(exts) {
			return hello, errors.New("extension truncated")
		}
		extData := exts[4 : 4+extDataLen]
		exts = exts[4+extDataLen:]
		if extType == extALPN && withALPN {
			protos, err := parseALPN(extData)
			if err != nil {
				return hello, err
			}
			hello.ALPN = protos
			continue
		}
		if extType != 0 {
			continue
		}
		// server_name extension: list_length(2) + entries
		// Each entry: name_type(1) + name_length(2) + name(N)
		if len(extData) < 5 {
			return hello, errors.New("server_name extension too short")
		}
		// Skip list_length (2 bytes); we just take the first entry.
		entry := extData[2:]
		if entry[0] != 0 { // host_name type
			return hello, errors.New("server_name entry is not host_name")
		}
		nameLen := int(entry[1])<<8 | int(entry[2])
		if 3+nameLen > len(entry) {
			return hello, errors.New("server_name truncated")
		}
		hello.SNI = string(entry[3 : 3+nameLen])
		if !withALPN {
			return hello, nil
		}
	}
	if withALPN {
		return hello, nil
	}
	return hello, errNoSNI
}

// extALPN is the application_layer_protocol_negotiation extension type.
const extALPN = 16

// parseALPN decodes an ALPN extension body: list_length(2) followed by
// entries of length(1) + protocol name. Empty names and any length mismatch
// are rejected.
func parseALPN(data []byte) ([]string, error) {
	if len(data) < 2 {
		return nil, errors.New("alpn extension too short")
	}
	listLen := int(data[0])<<8 | int(data[1])
	list := data[2:]
	if listLen == 0 || listLen != len(list) {
		return nil, errors.New("alpn list length mismatch")
	}
	var protos []string
	for len(list) > 0 {
		n := int(list[0])
		if n == 0 || 1+n > len(list) {
			return nil, errors.New("alpn protocol entry malformed")
		}
		protos = append(protos, string(list[1:1+n]))
		list = list[1+n:]
	}
	return protos, nil
}

// peekConn wraps a net.Conn so that Read() drains a buffered reader first,
// transparently replaying any bytes that bufio.Reader.Peek consumed from the
// underlying connection. Writes, deadlines, and Close pass through unchanged.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }
