package hypervisor

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

// defaultMaxHandshakeLine bounds how many bytes are read looking for the
// handshake's trailing newline, so a caller that never sends one can't hold
// a connection open reading unboundedly.
const defaultMaxHandshakeLine = 4096

// handshakeRequest is the single JSON line a caller sends before the
// connection turns into a raw byte relay to the target's console. Not
// exported: this is an internal wire detail of the hypervisor-agent
// listener, not a public API — the sentinel-side console router (#1756)
// that will actually originate these requests is a separate, not-yet-built
// component, and its exact shape may still change this framing.
type handshakeRequest struct {
	Token  string `json:"token"`
	Target string `json:"target"`
}

// Agent serves the hypervisor-agent's console-multiplex protocol: a caller
// connects, sends one JSON handshake line ({"token":"...","target":"..."}),
// and — once authorized — the connection becomes a raw, bidirectional relay
// to that target's console via Provider.
type Agent struct {
	// Token is the shared secret a caller must present in the handshake.
	// Matches the tunnel client's own pre-shared-token convention
	// (--token/CONTAINARIUM_TUNNEL_TOKEN) rather than introducing a new
	// credential system. Required — HandleConn refuses every request if
	// this is empty, since an empty Token would otherwise make an empty
	// presented token "valid".
	Token string

	// Provider opens the actual console stream once a request is
	// authorized.
	Provider ConsoleProvider

	// MaxHandshakeLine overrides defaultMaxHandshakeLine. Zero uses the
	// default; only tests need to set this.
	MaxHandshakeLine int
}

// Serve accepts connections on ln until ctx is cancelled or Accept fails,
// handling each one in its own goroutine.
func (a *Agent) Serve(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("hypervisor-agent: accept: %w", err)
			}
		}
		go a.HandleConn(ctx, conn)
	}
}

// HandleConn reads one handshake off conn, authorizes it, opens the
// requested console, and relays bytes until either side closes. It always
// closes conn before returning.
func (a *Agent) HandleConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	req, err := readHandshake(conn, a.maxHandshakeLine())
	if err != nil {
		writeAgentError(conn, err)
		return
	}
	if !tokenAuthorized(a.Token, req.Token) {
		writeAgentError(conn, errors.New("unauthorized"))
		return
	}
	if req.Target == "" {
		writeAgentError(conn, errors.New("target is required"))
		return
	}
	if a.Provider == nil {
		writeAgentError(conn, errors.New("no console provider configured"))
		return
	}

	console, err := a.Provider.OpenConsole(ctx, req.Target)
	if err != nil {
		writeAgentError(conn, err)
		return
	}
	defer func() { _ = console.Close() }()

	if _, err := conn.Write([]byte("ok\n")); err != nil {
		return
	}

	relay(conn, console)
}

func (a *Agent) maxHandshakeLine() int {
	if a.MaxHandshakeLine > 0 {
		return a.MaxHandshakeLine
	}
	return defaultMaxHandshakeLine
}

// readHandshake reads one newline-terminated JSON line from r and decodes
// it as a handshakeRequest.
//
// Deliberately reads one byte at a time rather than through a bufio.Reader:
// a buffered reader's first Read pulls a full internal buffer's worth from
// the underlying connection, and on a real socket that read can coalesce
// the handshake line together with whatever the caller sends immediately
// after it (the first chunk of console input, sent without waiting for the
// "ok" response). Those extra bytes would be captured in the bufio.Reader's
// internal buffer — which is discarded once the handshake is parsed — and
// never reach relay(), which reads directly off conn. A byte-at-a-time read
// never consumes past the delimiter, so nothing is lost. This mirrors
// internal/sentinel/tunnel_auth.go's readHandshakeLine, which hit the same
// class of bug for the same reason (its own comment calls out the identical
// "SYN frame" scenario for the tunnel handshake).
func readHandshake(r io.Reader, maxLine int) (handshakeRequest, error) {
	buf := make([]byte, 0, 256)
	one := make([]byte, 1)
	for {
		n, err := r.Read(one)
		if err != nil {
			return handshakeRequest{}, fmt.Errorf("hypervisor-agent: read handshake: %w", err)
		}
		if n == 0 {
			continue
		}
		if one[0] == '\n' {
			break
		}
		buf = append(buf, one[0])
		if len(buf) > maxLine {
			return handshakeRequest{}, fmt.Errorf("hypervisor-agent: handshake exceeded %d bytes", maxLine)
		}
	}

	var req handshakeRequest
	if err := json.Unmarshal(buf, &req); err != nil {
		return handshakeRequest{}, fmt.Errorf("hypervisor-agent: invalid handshake: %w", err)
	}
	return req, nil
}

// tokenAuthorized reports whether presented matches expected. Both must be
// non-empty — an unconfigured Agent.Token never authorizes anything, rather
// than an empty presented token matching an equally-empty expectation.
func tokenAuthorized(expected, presented string) bool {
	if expected == "" || presented == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) == 1
}

// writeAgentError sends a single-line, best-effort error to conn. Errors
// writing it are swallowed — the connection is being torn down either way.
func writeAgentError(conn net.Conn, err error) {
	log.Printf("[hypervisor-agent] rejecting connection from %s: %v", conn.RemoteAddr(), err)
	_, _ = conn.Write([]byte("error: " + err.Error() + "\n"))
}

// relay bidirectionally copies bytes between a and b until either side's
// copy finishes (EOF or error), then returns. Matches the tunnel client's
// own bidirectional-copy shape (internal/sentinel/tunnel_client.go).
func relay(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}
