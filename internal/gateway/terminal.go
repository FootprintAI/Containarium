package gateway

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
)

// PeerTerminalProxy resolves the WebSocket URL for a container on a peer backend.
// Returns empty string if the container is local or peers are not configured.
type PeerTerminalProxy interface {
	// PeerTerminalURL returns the WebSocket proxy URL for a container on a remote peer.
	// Returns ("", nil) if the container is local.
	PeerTerminalURL(username, authToken string) (string, error)
}

// TerminalHandler handles WebSocket terminal connections via Incus exec
type TerminalHandler struct {
	upgrader    websocket.Upgrader
	incusClient incus.InstanceServer
	peerProxy   PeerTerminalProxy
}

// NewTerminalHandler creates a new terminal handler
func NewTerminalHandler() (*TerminalHandler, error) {
	// Connect to local Incus socket
	client, err := incus.ConnectIncusUnix("", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Incus: %w", err)
	}

	return &TerminalHandler{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// SECURITY FIX: Validate WebSocket origin against allowed origins
				origin := r.Header.Get("Origin")
				if origin == "" {
					// No origin header - reject for security
					// (browsers always send Origin for cross-origin WebSocket)
					log.Printf("WebSocket connection rejected: no Origin header")
					return false
				}

				// Check against allowed origins
				allowedOrigins := getTerminalAllowedOrigins()
				for _, allowed := range allowedOrigins {
					if origin == allowed {
						return true
					}
				}

				log.Printf("WebSocket connection rejected: origin %s not in allowed list", origin)
				return false
			},
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		incusClient: client,
	}, nil
}

// getTerminalAllowedOrigins returns the list of allowed origins for WebSocket connections.
// Configurable via CONTAINARIUM_ALLOWED_ORIGINS environment variable (comma-separated).
// Defaults to localhost origins only for security.
func getTerminalAllowedOrigins() []string {
	envOrigins := os.Getenv("CONTAINARIUM_ALLOWED_ORIGINS")
	if envOrigins != "" {
		origins := strings.Split(envOrigins, ",")
		// Trim whitespace from each origin
		for i, origin := range origins {
			origins[i] = strings.TrimSpace(origin)
		}
		return origins
	}
	// Default to localhost only - secure by default
	return []string{
		"http://localhost:3000",
		"http://localhost:8080",
		"http://localhost",
	}
}

// TerminalMessage represents a message sent over WebSocket
type TerminalMessage struct {
	Type string `json:"type"` // "input", "output", "resize", "error"
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

// SetPeerProxy sets the peer terminal proxy for multi-backend routing.
func (th *TerminalHandler) SetPeerProxy(proxy PeerTerminalProxy) {
	th.peerProxy = proxy
}

// HandleTerminal handles WebSocket connections for container terminal
func (th *TerminalHandler) HandleTerminal(w http.ResponseWriter, r *http.Request) {
	// Extract username from URL path: /v1/containers/{username}/terminal
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	username := parts[3] // /v1/containers/{username}/terminal
	if username == "" {
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}

	containerName := username + "-container"

	// Check if container is on a peer backend
	if th.peerProxy != nil {
		authToken := r.URL.Query().Get("token")
		if peerURL, err := th.peerProxy.PeerTerminalURL(username, authToken); err == nil && peerURL != "" {
			// Proxy WebSocket to peer
			log.Printf("Proxying terminal for %s to peer: %s", containerName, peerURL)
			th.proxyWebSocket(w, r, peerURL, authToken)
			return
		}
	}

	// Verify container exists and is running locally
	state, _, err := th.incusClient.GetInstanceState(containerName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Container not found: %v", err), http.StatusNotFound)
		return
	}

	if state.Status != "Running" {
		http.Error(w, fmt.Sprintf("Container is not running (status: %s)", state.Status), http.StatusBadRequest)
		return
	}

	// Upgrade HTTP connection to WebSocket
	conn, err := th.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("Terminal WebSocket connected for container %s", containerName)

	// Start terminal session
	th.startTerminalSession(conn, containerName, username)
}

// proxyWebSocket proxies a WebSocket connection to a peer backend's terminal endpoint.
func (th *TerminalHandler) proxyWebSocket(w http.ResponseWriter, r *http.Request, peerURL, authToken string) {
	// Parse the peer URL and set up WebSocket dial
	u, err := url.Parse(peerURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid peer URL: %v", err), http.StatusInternalServerError)
		return
	}

	// Add auth token as query param
	q := u.Query()
	q.Set("token", authToken)
	u.RawQuery = q.Encode()

	// Dial the peer's WebSocket
	peerHeaders := http.Header{}
	peerConn, _, err := websocket.DefaultDialer.Dial(u.String(), peerHeaders)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to peer terminal: %v", err), http.StatusBadGateway)
		return
	}
	defer peerConn.Close()

	// Upgrade client connection
	clientConn, err := th.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed for proxy: %v", err)
		return
	}
	defer clientConn.Close()

	// Bidirectional proxy
	done := make(chan struct{})

	// Client → Peer
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			msgType, msg, err := clientConn.ReadMessage()
			if err != nil {
				return
			}
			if err := peerConn.WriteMessage(msgType, msg); err != nil {
				return
			}
		}
	}()

	// Peer → Client
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			msgType, msg, err := peerConn.ReadMessage()
			if err != nil {
				return
			}
			if err := clientConn.WriteMessage(msgType, msg); err != nil {
				return
			}
		}
	}()

	// Wait for either direction to close
	<-done
}

// startTerminalSession starts an interactive shell session in the container
func (th *TerminalHandler) startTerminalSession(conn *websocket.Conn, containerName string, username string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create pipes for stdin/stdout
	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()

	// Prepare exec request - run bash as the container user
	req := api.InstanceExecPost{
		Command:     []string{"su", "-", username}, // Login as the user
		WaitForWS:   true,
		Interactive: true,
		Width:       80,
		Height:      24,
	}

	// Execute command in container
	execArgs := incus.InstanceExecArgs{
		Stdin:    stdinReader,
		Stdout:   stdoutWriter,
		Stderr:   stdoutWriter,
		Control:  nil,
		DataDone: make(chan bool),
	}

	// Start exec operation
	op, err := th.incusClient.ExecInstance(containerName, req, &execArgs)
	if err != nil {
		log.Printf("Failed to start exec: %v", err)
		th.sendError(conn, fmt.Sprintf("Failed to start terminal: %v", err))
		return
	}

	// Create done channel
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			close(done)
			cancel()
		})
	}

	// Forward stdout to WebSocket
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := stdoutReader.Read(buf)
				if err != nil {
					if err != io.EOF {
						log.Printf("Stdout read error: %v", err)
					}
					closeDone()
					return
				}
				if n > 0 {
					msg := TerminalMessage{
						Type: "output",
						Data: string(buf[:n]),
					}
					if err := conn.WriteJSON(msg); err != nil {
						log.Printf("WebSocket write error: %v", err)
						closeDone()
						return
					}
				}
			}
		}
	}()

	// Read from WebSocket and forward to stdin
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				var msg TerminalMessage
				if err := conn.ReadJSON(&msg); err != nil {
					if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
						log.Printf("WebSocket read error: %v", err)
					}
					closeDone()
					return
				}

				switch msg.Type {
				case "input":
					if _, err := stdinWriter.Write([]byte(msg.Data)); err != nil {
						log.Printf("Stdin write error: %v", err)
						closeDone()
						return
					}
				case "resize":
					// Note: Incus doesn't easily support window resize after exec starts
					// Would need to use the control channel
					log.Printf("Resize requested: %dx%d (not yet implemented)", msg.Cols, msg.Rows)
				}
			}
		}
	}()

	// Wait for operation to complete
	go func() {
		err := op.Wait()
		if err != nil {
			log.Printf("Exec operation error: %v", err)
		}
		closeDone()
	}()

	// Wait for session to end
	<-done

	// Cleanup
	stdinWriter.Close()
	stdoutWriter.Close()

	log.Printf("Terminal session ended for container %s", containerName)
}

// sendError sends an error message over WebSocket
func (th *TerminalHandler) sendError(conn *websocket.Conn, message string) {
	msg := TerminalMessage{
		Type: "error",
		Data: message,
	}
	conn.WriteJSON(msg)
}
