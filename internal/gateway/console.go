package gateway

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/gorilla/websocket"
	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/ws"
)

// ConsoleHandler handles WebSocket live-attach connections to a VM
// instance's serial console via Incus's ConsoleInstance. Unlike
// TerminalHandler (an exec'd shell, JSON-framed for browser xterm.js
// resize support), a serial console is a dumb byte pipe — no PTY
// negotiation, no resize after attach — so this relays raw binary
// WebSocket frames directly.
type ConsoleHandler struct {
	upgrader    websocket.Upgrader
	incusClient incus.InstanceServer
}

// NewConsoleHandler creates a new console handler backed by the local
// Incus unix socket.
func NewConsoleHandler() (*ConsoleHandler, error) {
	client, err := incus.ConnectIncusUnix("", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Incus: %w", err)
	}

	return &ConsoleHandler{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					// No Origin header at all — this is the expected shape
					// for a non-browser client (the containarium CLI), which
					// is the only client this endpoint is built for today.
					return true
				}
				for _, allowed := range getTerminalAllowedOrigins() {
					if origin == allowed {
						return true
					}
				}
				log.Printf("console WebSocket connection rejected: origin %s not in allowed list", origin)
				return false
			},
			Subprotocols:    []string{auth.WSSubprotocolBearer},
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		incusClient: client,
	}, nil
}

// parseConsoleUsername extracts the username from a
// /v1/containers/{username}/console-attach path. Returns "" if the path
// doesn't match that shape.
func parseConsoleUsername(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	// ["v1", "containers", "{username}", "console-attach"]
	if len(parts) != 4 || parts[0] != "v1" || parts[1] != "containers" || parts[3] != "console-attach" {
		return ""
	}
	return parts[2]
}

// authorizeConsoleAccess reports whether claims may attach to
// requestedUsername's console: the subject must own the tenant or hold the
// admin role. Mirrors auth.AuthorizeTenant's decision exactly, adapted for
// an already-validated *auth.Claims (the gRPC-context form AuthorizeTenant
// reads doesn't exist on this HTTP/WebSocket upgrade path).
func authorizeConsoleAccess(claims *auth.Claims, requestedUsername string) error {
	if claims == nil {
		return fmt.Errorf("no authenticated subject")
	}
	if auth.HasRole(claims.Roles, auth.RoleAdmin) {
		return nil
	}
	if claims.Username != requestedUsername {
		return fmt.Errorf("not authorized for this tenant")
	}
	return nil
}

// HandleConsole upgrades the request to a WebSocket and relays raw bytes
// between the caller and the instance's serial console. Callers must
// already be authenticated and tenant-authorized (see
// authorizeConsoleAccess) — matching TerminalHandler's contract, that
// check happens in the route registration closure, not here.
func (ch *ConsoleHandler) HandleConsole(w http.ResponseWriter, r *http.Request) {
	username := parseConsoleUsername(r.URL.Path)
	if username == "" {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	containerName := username + "-container"

	state, _, err := ch.incusClient.GetInstanceState(containerName)
	if err != nil {
		http.Error(w, fmt.Sprintf("container not found: %v", err), http.StatusNotFound)
		return
	}
	if state.Status != "Running" {
		http.Error(w, fmt.Sprintf("container is not running (status: %s)", state.Status), http.StatusBadRequest)
		return
	}

	conn, err := ch.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("console WebSocket upgrade failed: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()

	log.Printf("console attached for container %s", containerName)
	ch.attachConsole(conn, containerName)
	log.Printf("console detached for container %s", containerName)
}

// attachConsole bridges conn (the caller's WebSocket) to the instance's
// serial console and blocks until the session ends. It does not depend on
// op.Wait()'s exact completion semantics for a clean detach: closing conn
// (a client-initiated close frame, or the connection simply dying) is
// observed via SetCloseHandler, which is what actually drives the
// ConsoleDisconnect signal telling Incus to detach without killing the
// instance — the same signal upstream's own `incus console` CLI relies on.
func (ch *ConsoleHandler) attachConsole(conn *websocket.Conn, containerName string) {
	disconnect := make(chan bool)
	var closeOnce sync.Once
	closeDisconnect := func() { closeOnce.Do(func() { close(disconnect) }) }

	conn.SetCloseHandler(func(code int, text string) error {
		closeDisconnect()
		return nil
	})

	op, err := ch.incusClient.ConsoleInstance(containerName, api.InstanceConsolePost{Type: "console"}, &incus.InstanceConsoleArgs{
		Terminal:          ws.NewWrapper(conn),
		Control:           func(*websocket.Conn) {}, // resize not meaningful for a serial console
		ConsoleDisconnect: disconnect,
	})
	if err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte("error: "+err.Error()))
		return
	}

	if err := op.Wait(); err != nil {
		log.Printf("console session for %s ended with error: %v", containerName, err)
	}
	closeDisconnect()
}
