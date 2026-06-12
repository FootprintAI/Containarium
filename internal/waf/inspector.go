package waf

import (
	"bytes"
	"net"
)

// Verdict is an Inspector's decision about a connection's request head.
type Verdict struct {
	Block    bool
	RuleID   uint16 // the matched rule/signature id (0 if none)
	RuleName string // human label for the audit log
}

// Inspector examines the start of a steered connection's payload — the request
// head, REASSEMBLED across TCP segments — and decides whether to block. The
// reassembly is the value over Tier 2's in-kernel scan, which only ever sees a
// single packet (a signature split across segments evades it). The interface is
// the seam a real WAF engine (Coraza + the OWASP CRS) plugs into later, behind a
// `waf` build tag; BuiltinInspector is the reference implementation that ships
// now with no extra dependency.
type Inspector interface {
	Inspect(head []byte) Verdict
}

// maxHeadBytes bounds how much of a connection's start is buffered for
// inspection — enough for an HTTP request line + headers (where header-borne
// exploits like Log4Shell live), capped so a slow/huge request can't exhaust
// memory. Bytes past the head still flow through, uninspected (documented best-
// effort limit; full body inspection is a WAF-engine refinement).
const maxHeadBytes = 16 * 1024

// block403 is the response written to a client whose request an Inspector blocked
// (enforce mode). Minimal + Connection: close so the proxy can tear the
// connection down cleanly without forwarding upstream.
var block403 = []byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")

// readHead reads from c until the end-of-headers marker ("\r\n\r\n"), max bytes,
// or EOF — whichever first — and returns everything read. Reassembles across
// however many TCP segments/reads the head spans. The returned bytes are
// forwarded verbatim to the upstream after inspection (byte-preserving proxy),
// so this consumes only the head; the rest of the stream is piped afterward.
func readHead(c net.Conn, max int) []byte {
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 2048)
	for len(buf) < max {
		n, err := c.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if bytes.Contains(buf, []byte("\r\n\r\n")) {
				break
			}
		}
		if err != nil {
			break // EOF / error before a full head — inspect what we have
		}
	}
	if len(buf) > max {
		buf = buf[:max]
	}
	return buf
}
