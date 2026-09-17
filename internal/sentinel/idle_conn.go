package sentinel

import (
	"net"
	"time"
)

// sniProxyIdleTimeout bounds how long the SNI-routing passthrough proxy
// (buildSNIRoutingHandler) waits for either side of a connection to send
// anything before giving up on it (#1349).
//
// Matches the IdleTimeout already used for the BYOC ingress HTTP server
// in this same package (startHTTPSProxy's sibling, serveBYOCIngress) —
// same philosophy, same value: bound an idle connection so its serving
// goroutine can't leak.
const sniProxyIdleTimeout = 120 * time.Second

// idleTimeoutConn wraps a net.Conn so every Read refreshes a rolling
// idle deadline before blocking (#1349).
//
// buildSNIRoutingHandler pumps a proxied connection with two io.Copy
// goroutines and waits for the first to return before closing both —
// but if the peer disappears without sending FIN or RST (the normal
// case for a powered-off or preempted backend, as opposed to a graceful
// shutdown), the blocked Read on that side never returns on its own:
// no bytes, no EOF, no error. Neither io.Copy call ever finishes, so
// the goroutines, their bufio.Reader (peekSNI) and 32KB copy buffers
// are retained until the process restarts — reproduced live as 2,730
// leaked connection pairs and ~330MB of retained memory in the space of
// 35 minutes.
//
// Wrapping the reader used by io.Copy so each Read call refreshes
// SetReadDeadline turns a silently vanished peer into a read timeout —
// io.Copy returns, the goroutine's copy finishes, the handler's
// deferred Close on both connections runs, and the timeout on the OTHER
// direction's Read (now reading from a closed connection) unblocks it
// too. An active connection never sees the deadline: it is pushed
// forward by sniProxyIdleTimeout on every single read, however small.
type idleTimeoutConn struct {
	net.Conn
	idleTimeout time.Duration
}

func (c *idleTimeoutConn) Read(b []byte) (int, error) {
	if err := c.SetReadDeadline(time.Now().Add(c.idleTimeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}
