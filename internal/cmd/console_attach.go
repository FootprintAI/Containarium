package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/gorilla/websocket"
	"golang.org/x/term"
)

// detachEscape is a byte-scanning io.Reader that watches for Incus's own
// detach sequence — <ctrl>+a then 'q' — so `containarium console` behaves
// the same way `incus console` does for anyone already used to it. Closing
// detach signals a clean detach without killing the target instance.
type detachEscape struct {
	r          io.Reader
	detach     chan struct{}
	once       sync.Once
	foundCtrlA bool
}

func newDetachEscape(r io.Reader) (*detachEscape, <-chan struct{}) {
	ch := make(chan struct{})
	return &detachEscape{r: r, detach: ch}, ch
}

func (d *detachEscape) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	for _, b := range p[:n] {
		switch {
		case b == '\x01': // <ctrl>+a
			d.foundCtrlA = true
		case b == 'q' && d.foundCtrlA:
			d.once.Do(func() { close(d.detach) })
			d.foundCtrlA = false
		default:
			d.foundCtrlA = false
		}
	}
	return n, err
}

// attachConsole opens a live, bidirectional connection to a VM instance's
// serial console. Unlike --log, this requires --http with an http(s)://
// --server: it needs a WebSocket upgrade, which a plain gRPC endpoint has
// no path for.
func attachConsole(username string) error {
	if !httpMode || serverAddr == "" {
		return fmt.Errorf("live console attach requires --http with an http(s):// --server address (the ring-buffer log via --log works over gRPC too)")
	}

	wsURL, err := consoleWebSocketURL(serverAddr, username)
	if err != nil {
		return err
	}

	headers := http.Header{}
	headers.Set("Sec-WebSocket-Protocol", auth.WSSubprotocolBearer+", "+authToken)

	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return fmt.Errorf("failed to attach console (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return fmt.Errorf("failed to attach console: %w", err)
	}
	defer func() { _ = conn.Close() }()

	stdinFd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return fmt.Errorf("failed to set raw terminal mode: %w", err)
	}
	defer func() { _ = term.Restore(stdinFd, oldState) }()

	fmt.Print("To detach from the console, press: <ctrl>+a q\r\n")

	stdin, detach := newDetachEscape(os.Stdin)
	done := make(chan struct{})

	// stdin -> console
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := stdin.Read(buf)
			if n > 0 {
				if writeErr := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); writeErr != nil {
					close(done)
					return
				}
			}
			if err != nil {
				close(done)
				return
			}
		}
	}()

	// console -> stdout
	go func() {
		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				close(done)
				return
			}
			if msgType == websocket.BinaryMessage {
				_, _ = os.Stdout.Write(data)
			}
		}
	}()

	select {
	case <-detach:
		closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "detaching")
		_ = conn.WriteMessage(websocket.CloseMessage, closeMsg)
	case <-done:
	}

	fmt.Print("\r\n")
	return nil
}

// consoleWebSocketURL builds the console-attach WebSocket URL from an
// http(s):// --server address.
func consoleWebSocketURL(serverAddr, username string) (string, error) {
	base := serverAddr
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	u, err := url.Parse(strings.TrimSuffix(base, "/"))
	if err != nil {
		return "", fmt.Errorf("invalid --server address: %w", err)
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return "", fmt.Errorf("unsupported --server scheme %q for console attach", u.Scheme)
	}
	// Path takes the decoded form (a literal "/" in username is just
	// another path separator there); RawPath carries the pre-escaped form
	// url.URL.String() actually serializes, matching how the HTTP client
	// escapes a username in its own container paths.
	u.Path = fmt.Sprintf("/v1/containers/%s/console-attach", username)
	u.RawPath = fmt.Sprintf("/v1/containers/%s/console-attach", url.PathEscape(username))
	return u.String(), nil
}
