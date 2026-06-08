package sentinel

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// TunnelServer listens for incoming tunnel connections from remote spot instances.
// Each connected spot gets a loopback alias, and the server opens local TCP proxy
// listeners that forward traffic through the yamux session to the spot.
type TunnelServer struct {
	listenAddr string
	policy     *TokenPolicy
	registry   *TunnelRegistry

	// Callbacks for Manager integration
	OnConnect    func(spot *TunnelSpot)
	OnDisconnect func(spot *TunnelSpot)

	// Active proxy listeners per spot (spotID -> list of listeners)
	mu        sync.Mutex
	proxies   map[string][]net.Listener
	cancelCtx context.CancelFunc
}

// NewTunnelServer creates a new tunnel server with a token-bound pool
// authorization policy. To preserve the legacy single-token behavior
// (any pool allowed), pass a policy with a single rule:
//
//	policy := NewTokenPolicy()
//	policy.Allow(token, "*")
//	srv := NewTunnelServer(addr, policy, registry)
func NewTunnelServer(listenAddr string, policy *TokenPolicy, registry *TunnelRegistry) *TunnelServer {
	return &TunnelServer{
		listenAddr: listenAddr,
		policy:     policy,
		registry:   registry,
		proxies:    make(map[string][]net.Listener),
	}
}

// Run starts the tunnel server on its own port. Blocks until ctx is cancelled.
func (ts *TunnelServer) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", ts.listenAddr)
	if err != nil {
		return fmt.Errorf("tunnel server listen on %s: %w", ts.listenAddr, err)
	}
	defer func() { _ = ln.Close() }()

	log.Printf("[tunnel-server] listening on %s", ts.listenAddr)
	return ts.Serve(ctx, ln)
}

// Serve accepts tunnel connections from the given listener. Use this when the
// listener is provided externally (e.g., from a ConnMux). Blocks until ctx is
// cancelled or the listener is closed.
func (ts *TunnelServer) Serve(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	ts.cancelCtx = cancel

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				// Check if the listener was closed (net.ErrClosed or similar)
				if isClosedErr(err) {
					return nil
				}
				log.Printf("[tunnel-server] accept error: %v", err)
				continue
			}
		}
		go ts.handleConnection(ctx, conn)
	}
}

func (ts *TunnelServer) handleConnection(ctx context.Context, conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[tunnel-server] new connection from %s", remoteAddr)

	// Set deadline for handshake
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Read handshake
	hs, err := readHandshake(conn)
	if err != nil {
		log.Printf("[tunnel-server] handshake read error from %s: %v", remoteAddr, err)
		_ = conn.Close()
		return
	}

	// Validate
	if err := validateHandshake(hs, ts.policy); err != nil {
		log.Printf("[tunnel-server] handshake validation failed from %s: %v", remoteAddr, err)
		_ = writeHandshakeResponse(conn, &TunnelHandshakeResponse{OK: false, Error: err.Error()})
		_ = conn.Close()
		return
	}

	// Clear deadline after successful handshake validation
	_ = conn.SetDeadline(time.Time{})

	// Create yamux session. The sentinel is the yamux *client* (it opens streams
	// to dial into the spot), even though the TCP connection was initiated by the spot.
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.EnableKeepAlive = true
	// Generous timeouts so tunnel survives CPU-heavy workloads on peers
	yamuxCfg.KeepAliveInterval = 60 * time.Second
	yamuxCfg.ConnectionWriteTimeout = 60 * time.Second

	session, err := yamux.Client(conn, yamuxCfg)
	if err != nil {
		log.Printf("[tunnel-server] yamux client creation failed for %s: %v", hs.SpotID, err)
		_ = writeHandshakeResponse(conn, &TunnelHandshakeResponse{OK: false, Error: "yamux init failed"})
		_ = conn.Close()
		return
	}

	// Register in the registry (assigns loopback alias)
	localIP, err := ts.registry.Register(hs, session)
	if err != nil {
		log.Printf("[tunnel-server] registration failed for %s: %v", hs.SpotID, err)
		_ = writeHandshakeResponse(conn, &TunnelHandshakeResponse{OK: false, Error: err.Error()})
		_ = session.Close()
		return
	}

	// Send success response
	if err := writeHandshakeResponse(conn, &TunnelHandshakeResponse{OK: true, AssignedIP: localIP}); err != nil {
		log.Printf("[tunnel-server] failed to send handshake response to %s: %v", hs.SpotID, err)
		ts.registry.Unregister(hs.SpotID)
		_ = session.Close()
		return
	}

	log.Printf("[tunnel-server] spot %q authenticated, assigned %s, ports %v", hs.SpotID, localIP, hs.Ports)

	// Start local TCP proxy listeners for each port. Skip the public
	// port for tunnel-promoted primaries — the sentinel's own ConnMux
	// owns it, and the SNI router uses TunnelRegistry.DialTunnel() to
	// stream bytes via yamux instead.
	externalPort := 0
	if spot := ts.registry.Get(hs.SpotID); spot != nil {
		externalPort = spot.ExternalPort
	}
	loopbackPorts := hs.Ports
	if hs.PublicHostname != "" && hs.PublicPort != 0 {
		filtered := make([]int, 0, len(hs.Ports))
		for _, p := range hs.Ports {
			if p == hs.PublicPort {
				continue
			}
			filtered = append(filtered, p)
		}
		loopbackPorts = filtered
	}
	ts.startProxies(ctx, hs.SpotID, localIP, externalPort, loopbackPorts, session)

	// Notify manager
	spot := ts.registry.Get(hs.SpotID)
	if spot != nil && ts.OnConnect != nil {
		ts.OnConnect(spot)
	}

	// Monitor session — when it closes, clean up
	go ts.monitorSession(hs.SpotID, session)
}

// startProxies opens a local TCP listener on localIP:port for each port.
// Connections to these listeners are proxied through the yamux session.
// If binding to localIP fails (e.g., loopback alias not available on non-Linux),
// it falls back to 127.0.0.1.
// For the health port (8080), it also binds on 0.0.0.0:externalPort so that
// the primary daemon on another VM can reach this tunnel backend's API.
func (ts *TunnelServer) startProxies(ctx context.Context, spotID, localIP string, externalPort int, ports []int, session *yamux.Session) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Close any existing proxies for this spot
	ts.closeProxiesLocked(spotID)

	var listeners []net.Listener
	for _, port := range ports {
		// Use a high-port offset for port 22 to avoid conflicting with sshpiper
		// which binds *:22. The offset port (e.g., 20022) is used in sshpiper
		// config so that tunnel SSH traffic goes: sshpiper -> 127.0.0.x:20022
		// -> yamux tunnel -> spot:22.
		listenPort := port
		if port == 22 {
			listenPort = 20022
		}
		addr := fmt.Sprintf("%s:%d", localIP, listenPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			// Fall back to 127.0.0.1 if the loopback alias isn't available
			fallbackAddr := fmt.Sprintf("127.0.0.1:%d", listenPort)
			ln, err = net.Listen("tcp", fallbackAddr)
			if err != nil {
				log.Printf("[tunnel-server] failed to listen on %s (and fallback %s) for spot %s: %v", addr, fallbackAddr, spotID, err)
				continue
			}
			log.Printf("[tunnel-server] proxy listening on %s (fallback) → tunnel → spot %s (remote port %d)", fallbackAddr, spotID, port)
		} else {
			log.Printf("[tunnel-server] proxy listening on %s → tunnel → spot %s (remote port %d)", addr, spotID, port)
		}
		listeners = append(listeners, ln)
		go ts.proxyLoop(ctx, ln, port, session, spotID)

		// For the health/API port (8080), also bind on an externally reachable port
		// so the primary daemon can reach this tunnel backend
		if port == 8080 && externalPort > 0 {
			extAddr := fmt.Sprintf("0.0.0.0:%d", externalPort)
			extLn, extErr := net.Listen("tcp", extAddr)
			if extErr != nil {
				log.Printf("[tunnel-server] failed to bind external port %s for spot %s: %v", extAddr, spotID, extErr)
			} else {
				log.Printf("[tunnel-server] external proxy listening on %s → tunnel → spot %s (for peer discovery)", extAddr, spotID)
				listeners = append(listeners, extLn)
				go ts.proxyLoop(ctx, extLn, port, session, spotID)
			}
		}
	}
	ts.proxies[spotID] = listeners
}

// proxyLoop accepts connections on the local listener and forwards them
// through the yamux session to the spot's corresponding port.
func (ts *TunnelServer) proxyLoop(ctx context.Context, ln net.Listener, port int, session *yamux.Session, spotID string) {
	for {
		localConn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				// Listener closed (spot disconnected)
				return
			}
		}
		go ts.proxyConnection(localConn, port, session, spotID)
	}
}

// proxyConnection forwards a single connection through yamux to the spot.
// The protocol: the sentinel opens a yamux stream, sends a 2-byte port number,
// then does bidirectional copy.
func (ts *TunnelServer) proxyConnection(localConn net.Conn, port int, session *yamux.Session, spotID string) {
	defer func() { _ = localConn.Close() }()

	// Open a yamux stream to the spot
	stream, err := session.Open()
	if err != nil {
		log.Printf("[tunnel-server] failed to open yamux stream to spot %s for port %d: %v", spotID, port, err)
		return
	}
	defer func() { _ = stream.Close() }()

	// Send the target port as a 2-byte big-endian header
	portBytes := []byte{byte(port >> 8), byte(port & 0xff)}
	if _, err := stream.Write(portBytes); err != nil {
		log.Printf("[tunnel-server] failed to write port header to spot %s: %v", spotID, err)
		return
	}

	// Bidirectional copy — close write sides to propagate EOF properly
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(stream, localConn)
		if cs, ok := stream.(interface{ CloseWrite() error }); ok {
			_ = cs.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(localConn, stream)
		if tc, ok := localConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
}

// monitorSession watches for the yamux session to close and triggers cleanup.
func (ts *TunnelServer) monitorSession(spotID string, session *yamux.Session) {
	// Wait for the session to close (this blocks until the underlying conn dies
	// or the session is explicitly closed)
	<-session.CloseChan()

	log.Printf("[tunnel-server] spot %q session closed, cleaning up", spotID)

	// Get spot info before unregistering (for callback)
	spot := ts.registry.Get(spotID)

	// Close proxy listeners
	ts.mu.Lock()
	ts.closeProxiesLocked(spotID)
	ts.mu.Unlock()

	// Unregister from registry (removes loopback alias)
	ts.registry.Unregister(spotID)

	// Notify manager
	if spot != nil && ts.OnDisconnect != nil {
		ts.OnDisconnect(spot)
	}
}

// isClosedErr returns true if the error indicates a closed connection/listener.
func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	return err == net.ErrClosed ||
		strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "closed")
}

func (ts *TunnelServer) closeProxiesLocked(spotID string) {
	if listeners, ok := ts.proxies[spotID]; ok {
		for _, ln := range listeners {
			_ = ln.Close()
		}
		delete(ts.proxies, spotID)
	}
}
