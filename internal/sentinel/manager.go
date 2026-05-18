package sentinel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// State represents the current sentinel mode.
type State string

const (
	StateProxy       State = "proxy"
	StateMaintenance State = "maintenance"
)

// Config holds the sentinel configuration.
type Config struct {
	HealthPort         int
	CheckInterval      time.Duration
	HTTPPort           int
	HTTPSPort          int
	ForwardedPorts     []int
	HealthyThreshold   int
	UnhealthyThreshold int
	BinaryPort         int           // port to serve containarium binary for spot VM downloads (0 = disabled)
	RecoveryTimeout    time.Duration // warn if recovery takes longer than this (0 = no warning)
	CertSyncInterval   time.Duration // interval for syncing TLS certs from backend (0 = default 6h)
	KeySyncInterval    time.Duration // interval for syncing SSH keys from backend (0 = default 2m)
	TunnelMode         bool          // if true, the Manager waits for tunnel connections instead of resolving IP at startup
	HybridMode         bool          // if true, GCP + tunnel backends coexist
	ProxyProtocol      bool          // if true, prepend a PROXY v2 header to forwarded HTTPS streams so the downstream Caddy sees the real client IP
}

// Manager is the core sentinel orchestrator.
// It health-checks backend VMs and switches between proxy and maintenance modes.
// Supports multiple backends (GCP + tunnel) in hybrid mode.
type Manager struct {
	config   Config
	provider CloudProvider // primary provider (GCP in hybrid mode)

	state atomic.Value // holds State

	// Multi-backend support
	mu       sync.RWMutex
	backends *BackendPool
	primary  *Backend // currently active backend for HTTP forwarding

	// Primary daemon registry (one entry per pool, populated by daemon
	// self-registration). Used by the SNI router for hostname-based dispatch.
	primaries *PrimaryRegistry

	// Tunnel registry (set by cmd/sentinel.go via SetTunnelRegistry). Lets
	// the SNI router open a yamux stream directly to tunnel-promoted
	// primaries instead of going through a loopback TCP proxy listener
	// — which would collide with the sentinel's own ConnMux on :443.
	tunnelRegistry *TunnelRegistry

	stopMaintenance func() // stops the HTTP/HTTPS maintenance servers
	certStore       *CertStore
	keyStore        *KeyStore

	// Tunnel/hybrid mode: ConnMux-based HTTPS handling
	httpsDispatch  *dispatchListener // from ConnMux, dispatches to proxy or maintenance

	// Simple-proxy mode (no ConnMux): userspace TCP forwarder used when
	// --proxy-protocol is set, so connections to :80/:443 traverse a Go
	// process that can prepend a PROXY v2 header instead of going through
	// kernel iptables DNAT (which can't inject headers and therefore
	// destroys the real client IP via MASQUERADE).
	userspaceFwd *userspaceForwarder

	// Recovery tracking
	outageStart    time.Time // when the current outage began
	lastPreemption time.Time // when the last preemption event was detected
	preemptCount   int       // total preemption events observed
}

// NewManager creates a new sentinel manager.
func NewManager(config Config, provider CloudProvider) *Manager {
	m := &Manager{
		config:    config,
		provider:  provider,
		backends:  NewBackendPool(),
		primaries: NewPrimaryRegistry(),
		certStore: NewCertStore(),
		keyStore:  NewKeyStore(),
	}
	m.state.Store(StateMaintenance)
	return m
}

// SetTunnelRegistry wires in the tunnel registry so the SNI router can open
// yamux streams directly to tunnel-promoted primaries. Optional — if unset,
// the SNI router falls back to TCP-dialing the primary's IP:Port.
func (m *Manager) SetTunnelRegistry(reg *TunnelRegistry) {
	m.tunnelRegistry = reg
}

// SetHTTPSListener sets a ConnMux HTTPS chanListener for tunnel/hybrid mode.
// The manager wraps it in a dispatchListener to swap between proxy and maintenance.
func (m *Manager) SetHTTPSListener(ln *chanListener) {
	m.httpsDispatch = newDispatchListener(ln)
}

// PeersHandler returns an HTTP handler that serves the list of tunnel backend peers.
// This allows the primary daemon to discover tunnel backends and their reachable addresses.
//
// Optional query parameter:
//
//	?pool=<name>  Return only peers in the named pool. Pass ?pool= (empty value)
//	              to return only peers without a pool tag. Omit the parameter
//	              entirely to return all peers (back-compat default).
func (m *Manager) PeersHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type peerInfo struct {
			ID        string `json:"id"`
			ProxyPath string `json:"proxy_path"` // path prefix on binary server, e.g. "/peer/tunnel-fts-5900x-gpu"
			Healthy   bool   `json:"healthy"`
			Pool      Pool   `json:"pool,omitempty"`
		}

		poolFilter, hasPoolFilter := r.URL.Query()["pool"]
		var wantPool Pool
		if hasPoolFilter {
			wantPool = Pool(poolFilter[0])
		}

		backends := m.backends.All()
		peers := make([]peerInfo, 0)
		for _, b := range backends {
			if b.Type != BackendTunnel {
				continue
			}
			if hasPoolFilter && b.Pool != wantPool {
				continue
			}
			peers = append(peers, peerInfo{
				ID:        b.ID,
				ProxyPath: "/peer/" + b.ID,
				Healthy:   b.Healthy,
				Pool:      b.Pool,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"peers": peers,
		})
	}
}

// PrimariesHandler returns an HTTP handler that serves the primary registry.
//
// Methods:
//
//	GET    /sentinel/primaries           list all live primaries (optional ?pool=)
//	POST   /sentinel/primaries           register a primary (body: Primary JSON)
//	PUT    /sentinel/primaries/{pool}    heartbeat (refresh LastHeartbeat)
//	DELETE /sentinel/primaries/{pool}    unregister
//
// Stale entries (no heartbeat within PrimaryTTL) are excluded from GET.
func (m *Manager) PrimariesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Path is either "/sentinel/primaries" or "/sentinel/primaries/{pool}"
		rest := strings.TrimPrefix(r.URL.Path, "/sentinel/primaries")
		rest = strings.TrimPrefix(rest, "/")
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodGet && rest == "":
			poolFilter, hasPoolFilter := r.URL.Query()["pool"]
			var wantPool Pool
			if hasPoolFilter {
				wantPool = Pool(poolFilter[0])
			}
			out := make([]*Primary, 0)
			for _, p := range m.primaries.All() {
				if hasPoolFilter && p.Pool != wantPool {
					continue
				}
				out = append(out, p)
			}
			json.NewEncoder(w).Encode(map[string]any{"primaries": out})

		case r.Method == http.MethodPost && rest == "":
			var p Primary
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
				return
			}
			if p.IP == "" {
				// Fall back to the request's source IP — saves the daemon
				// from having to know its own routable IP.
				if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
					p.IP = host
				}
			}
			if p.Pool == "" || p.Hostname == "" || p.IP == "" || p.Port == 0 {
				http.Error(w, `{"error":"pool, hostname, port required (ip optional, inferred from RemoteAddr)"}`, http.StatusBadRequest)
				return
			}
			stored := m.primaries.Register(p)
			log.Printf("[sentinel] primary registered: pool=%q host=%q base_domains=%v ip=%s:%d", stored.Pool, stored.Hostname, stored.BaseDomains, stored.IP, stored.Port)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(stored)

		case r.Method == http.MethodPut && rest != "":
			updated := m.primaries.Heartbeat(Pool(rest))
			if updated == nil {
				http.Error(w, `{"error":"pool not registered"}`, http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(updated)

		case r.Method == http.MethodDelete && rest != "":
			if !m.primaries.Unregister(Pool(rest)) {
				http.Error(w, `{"error":"pool not registered"}`, http.StatusNotFound)
				return
			}
			log.Printf("[sentinel] primary unregistered: pool=%q", rest)
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
	}
}

// Run is the main loop. Blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	log.Printf("[sentinel] starting (check-interval=%s, health-port=%d, forwarded-ports=%v, hybrid=%v)",
		m.config.CheckInterval, m.config.HealthPort, m.config.ForwardedPorts, m.config.HybridMode)

	// Start binary server if configured (also serves /sentinel/peers for peer discovery)
	if m.config.BinaryPort > 0 {
		stopBinary, err := StartBinaryServer(m.config.BinaryPort, m)
		if err != nil {
			log.Printf("[sentinel] warning: binary server not started: %v", err)
		} else {
			defer stopBinary()
		}
	}

	if m.config.TunnelMode && !m.config.HybridMode {
		// Pure tunnel mode: wait for tunnel connections
		log.Printf("[sentinel] tunnel mode: waiting for remote spot to connect...")
	} else if m.config.HybridMode {
		// Hybrid mode: resolve GCP backend, also accept tunnels
		if err := m.initGCPBackend(ctx); err != nil {
			return err
		}
		log.Printf("[sentinel] hybrid mode: GCP backend active, also accepting tunnel connections...")
	} else {
		// Standard GCP-only mode
		if err := m.initGCPBackend(ctx); err != nil {
			return err
		}
	}

	// Start in maintenance mode
	if err := m.switchToMaintenance(); err != nil {
		return err
	}

	// Start event watcher if provider supports it (GCP preemption detection)
	eventCh := make(chan VMEvent, 10)
	if watcher, ok := m.provider.(EventWatcher); ok {
		go func() {
			log.Printf("[sentinel] event watcher started (polling GCP operations every 10s)")
			if err := watcher.WatchEvents(ctx, eventCh); err != nil {
				log.Printf("[sentinel] event watcher error: %v", err)
			}
		}()
	}

	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[sentinel] shutting down...")
			m.cleanup()
			return nil

		case event := <-eventCh:
			m.handleEvent(ctx, event)

		case <-ticker.C:
			m.healthCheckAll(ctx)
		}
	}
}

// initGCPBackend resolves the GCP spot VM IP and registers it as a backend.
func (m *Manager) initGCPBackend(ctx context.Context) error {
	ip, err := m.provider.GetInstanceIP(ctx)
	if err != nil {
		return err
	}

	b := &Backend{
		ID:       "gcp",
		Type:     BackendGCP,
		IP:       ip,
		Provider: m.provider,
		Priority: 0, // GCP is highest priority for HTTP
	}
	m.backends.Add(b)

	// Start sync loops for GCP backend
	m.startSyncLoops(ctx, b)

	log.Printf("[sentinel] GCP backend registered: %s", ip)
	return nil
}

// startSyncLoops starts cert and key sync loops for a backend.
func (m *Manager) startSyncLoops(parentCtx context.Context, b *Backend) {
	ctx, cancel := context.WithCancel(parentCtx)
	b.syncCancel = cancel

	certInterval := m.config.CertSyncInterval
	if certInterval == 0 {
		certInterval = 6 * time.Hour
	}
	go m.certStore.RunSyncLoop(ctx, b.IP, m.config.HealthPort, certInterval)

	keyInterval := m.config.KeySyncInterval
	if keyInterval == 0 {
		keyInterval = 2 * time.Minute
	}
	go m.keyStore.RunSyncLoop(ctx, b.ID, b.IP, m.config.HealthPort, keyInterval)
}

// healthCheckAll runs health checks on all registered backends and manages state transitions.
func (m *Manager) healthCheckAll(ctx context.Context) {
	backends := m.backends.All()
	if len(backends) == 0 {
		// No backends registered (pure tunnel mode, no tunnel connected yet)
		return
	}

	anyHealthy := false
	for _, b := range backends {
		healthy := CheckHealth(b.IP, m.config.HealthPort, 5*time.Second)

		if healthy {
			b.unhealthyCount = 0
			b.healthyCount++
			if b.healthyCount >= m.config.HealthyThreshold && !b.Healthy {
				b.Healthy = true
				log.Printf("[sentinel] backend %s (%s) is healthy", b.ID, b.IP)
			}
		} else {
			b.healthyCount = 0
			b.unhealthyCount++
			if b.unhealthyCount >= m.config.UnhealthyThreshold && b.Healthy {
				b.Healthy = false
				log.Printf("[sentinel] backend %s (%s) is unhealthy", b.ID, b.IP)

				// If this was the primary, try failover
				m.mu.RLock()
				wasPrimary := m.primary == b
				m.mu.RUnlock()
				if wasPrimary {
					m.failoverPrimary(ctx, b)
				}
			}
		}

		if b.Healthy {
			anyHealthy = true
		}
	}

	// State transitions
	if anyHealthy && m.currentState() == StateMaintenance {
		best := m.backends.SelectPrimary()
		if best != nil {
			log.Printf("[sentinel] backend available, switching to proxy via %s (%s)", best.ID, best.IP)
			if err := m.switchToProxy(best); err != nil {
				log.Printf("[sentinel] failed to switch to proxy: %v", err)
			}
		}
	}
	if !anyHealthy && m.currentState() == StateProxy {
		log.Printf("[sentinel] all backends unhealthy, switching to maintenance")
		m.outageStart = time.Now()
		if err := m.switchToMaintenance(); err != nil {
			log.Printf("[sentinel] failed to switch to maintenance: %v", err)
		}
		// Try to recover GCP backend
		for _, b := range backends {
			if b.Type == BackendGCP && b.Provider != nil {
				m.diagnoseAndRecover(ctx, b)
			}
		}
	}
}

// failoverPrimary switches HTTP forwarding to the next healthy backend.
func (m *Manager) failoverPrimary(ctx context.Context, failed *Backend) {
	next := m.backends.SelectPrimary()
	if next != nil && next != failed {
		log.Printf("[sentinel] failover: %s → %s (%s)", failed.ID, next.ID, next.IP)
		if err := m.switchToProxy(next); err != nil {
			log.Printf("[sentinel] failover failed: %v", err)
		}
	} else {
		log.Printf("[sentinel] no healthy backend for failover, switching to maintenance")
		m.outageStart = time.Now()
		if err := m.switchToMaintenance(); err != nil {
			log.Printf("[sentinel] failed to switch to maintenance: %v", err)
		}
		// Try to recover the failed backend
		if failed.Provider != nil {
			m.diagnoseAndRecover(ctx, failed)
		}
	}
}

func (m *Manager) currentState() State {
	return m.state.Load().(State)
}

func (m *Manager) switchToProxy(backend *Backend) error {
	// Stop maintenance HTTP servers
	if m.stopMaintenance != nil {
		m.stopMaintenance()
		m.stopMaintenance = nil
	}

	m.mu.Lock()
	m.primary = backend
	m.mu.Unlock()

	// Immediate cert sync from the primary backend
	if err := m.certStore.Sync(backend.IP, m.config.HealthPort); err != nil {
		log.Printf("[sentinel] cert sync on proxy switch failed: %v", err)
	} else {
		log.Printf("[sentinel] cert sync on proxy switch: %d certs", m.certStore.SyncedCount())
	}

	// Immediate key sync from ALL healthy backends + apply
	for _, b := range m.backends.Healthy() {
		if err := m.keyStore.Sync(b.ID, b.IP, m.config.HealthPort); err != nil {
			log.Printf("[sentinel] key sync for %s on proxy switch failed: %v", b.ID, err)
		}
		if err := m.keyStore.PushSentinelKey(b.IP, m.config.HealthPort); err != nil {
			log.Printf("[sentinel] push sentinel key for %s failed: %v", b.ID, err)
		}
	}
	if err := m.keyStore.Apply(); err != nil {
		log.Printf("[sentinel] key apply on proxy switch failed: %v", err)
	} else {
		log.Printf("[sentinel] key sync on proxy switch: %d users", m.keyStore.SyncedCount())
		m.keyStore.RestartSSHPiper()
	}

	// Handle port 443 via ConnMux if available (tunnel/hybrid mode)
	forwardedPorts := m.config.ForwardedPorts
	if m.httpsDispatch != nil {
		forwardedPorts = excludePort(forwardedPorts, m.config.HTTPSPort)
		m.startHTTPSProxy(backend.IP)
	}

	// Simple-proxy mode with --proxy-protocol: route :80/:443 through a
	// userspace TCP forwarder that prepends a PROXY v2 header. Kernel
	// iptables DNAT can't inject the frame, so without this path the
	// downstream Caddy never sees the real client IP. Only applies in
	// non-ConnMux mode — ConnMux already emits PROXY v2 via the SNI
	// router for its own :443 traffic.
	if m.config.ProxyProtocol && m.httpsDispatch == nil {
		userspacePorts := []int{m.config.HTTPPort, m.config.HTTPSPort}
		forwardedPorts = excludePort(forwardedPorts, m.config.HTTPPort)
		forwardedPorts = excludePort(forwardedPorts, m.config.HTTPSPort)

		fwd := newUserspaceForwarder(true)
		if err := fwd.start(backend.IP, userspacePorts); err != nil {
			fwd.stop()
			return fmt.Errorf("userspace forwarder: %w", err)
		}
		m.userspaceFwd = fwd
		log.Printf("[sentinel] userspace forwarder active for ports %v → %s (PROXY v2 enabled)",
			userspacePorts, backend.IP)
	}

	// Enable iptables forwarding for any remaining ports (everything
	// except the ones owned by ConnMux or the userspace forwarder).
	if err := enableForwarding(backend.IP, forwardedPorts); err != nil {
		return err
	}

	m.state.Store(StateProxy)
	log.Printf("[sentinel] mode: PROXY → primary=%s (%s), total backends=%d",
		backend.ID, backend.IP, m.backends.Count())
	return nil
}

func (m *Manager) switchToMaintenance() error {
	if err := disableForwarding(); err != nil {
		log.Printf("[sentinel] warning: failed to disable forwarding: %v", err)
	}

	// Tear down the userspace forwarder if it was running. Safe to call
	// even when it wasn't started — stop() on an empty listener list is
	// a no-op.
	if m.userspaceFwd != nil {
		m.userspaceFwd.stop()
		m.userspaceFwd = nil
	}

	m.mu.Lock()
	m.primary = nil
	m.mu.Unlock()

	// If ConnMux is active, switch HTTPS dispatch to maintenance mode
	if m.httpsDispatch != nil {
		m.setHTTPSMaintenanceHandler()
	}

	if m.stopMaintenance == nil {
		if m.httpsDispatch != nil {
			// ConnMux mode: only start HTTP maintenance on port 80
			stop, err := startMaintenanceHTTPOnly(m.config.HTTPPort, m)
			if err != nil {
				return err
			}
			m.stopMaintenance = stop
		} else {
			stop, err := startMaintenanceServers(m.config.HTTPPort, m.config.HTTPSPort, m.certStore, m)
			if err != nil {
				return err
			}
			m.stopMaintenance = stop
		}
	}

	m.state.Store(StateMaintenance)
	log.Printf("[sentinel] mode: MAINTENANCE → serving maintenance page")
	return nil
}

// startHTTPSProxy sets the dispatch handler to proxy HTTPS to the primary backend.
// HTTPS is forwarded as raw TCP (TLS passthrough) so the backend (Caddy) handles
// TLS termination with real Let's Encrypt certificates.
//
// Routing precedence per connection:
//  1. If the TLS ClientHello carries an SNI hostname registered in
//     m.primaries, forward to that primary's IP:Port.
//  2. Otherwise (no SNI, unknown hostname, or non-TLS), forward to backendIP
//     as before — preserves single-pool / unpooled behavior.
func (m *Manager) startHTTPSProxy(backendIP string) {
	fallback := net.JoinHostPort(backendIP, fmt.Sprintf("%d", m.config.HTTPSPort))
	m.httpsDispatch.SetHandler(m.buildSNIRoutingHandler(fallback))
	log.Printf("[sentinel] HTTPS proxy started → fallback %s (SNI routing via primary registry)", fallback)
}

// buildSNIRoutingHandler returns a connection handler that peeks SNI from
// each incoming TLS ClientHello and forwards the connection to the primary
// registered for that hostname, falling back to fallbackTarget on miss.
//
// Routing precedence:
//  1. Exact Hostname/Alias match (LookupByHostname).
//  2. BaseDomain suffix match (LookupByBaseDomainSuffix) — routes ad-hoc
//     container subdomains like "blog.containarium.dev" to whichever
//     primary registered BaseDomain="containarium.dev". See
//     docs/PER-POOL-BASE-DOMAIN.md.
//  3. No primary match → TCP-dial fallbackTarget (legacy single-backend
//     behavior).
//
// Inside each match path, the dial target depends on whether the primary
// is tunnel-promoted: BackendID set → yamux stream via the tunnel
// registry (avoids a sentinel-side TCP listener that would collide with
// ConnMux on :443); BackendID empty → TCP dial to Primary.IP:Port.
func (m *Manager) buildSNIRoutingHandler(fallbackTarget string) func(net.Conn) {
	return func(conn net.Conn) {
		defer conn.Close()

		// Bound the SNI peek so a stalled client can't hold the connection.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		sni, peekedConn, peekErr := peekSNI(conn)
		_ = conn.SetReadDeadline(time.Time{})

		var (
			dst net.Conn
			err error
		)
		if peekErr == nil && sni != "" {
			p := m.primaries.LookupByHostname(sni)
			if p == nil {
				p = m.primaries.LookupByBaseDomainSuffix(sni)
			}
			if p != nil {
				if p.BackendID != "" && m.tunnelRegistry != nil {
					// Tunnel-promoted primary: yamux directly.
					spotID := strings.TrimPrefix(p.BackendID, "tunnel-")
					dst, err = m.tunnelRegistry.DialTunnel(spotID, p.Port)
				} else {
					// In-VPC primary: TCP dial.
					target := net.JoinHostPort(p.IP, fmt.Sprintf("%d", p.Port))
					dst, err = net.DialTimeout("tcp", target, 5*time.Second)
				}
			}
		}
		if dst == nil {
			// No primary match (or yamux/TCP failed): fall back.
			dst, err = net.DialTimeout("tcp", fallbackTarget, 5*time.Second)
		}
		if err != nil || dst == nil {
			return
		}
		defer dst.Close()

		// Optionally prepend a PROXY v2 header so the downstream Caddy can
		// recover the real client IP (otherwise it sees the sentinel/loopback
		// peer of the forwarded TCP stream). Must be written before any TLS
		// bytes — peekedConn replays the ClientHello starting at the next
		// Read on our side, but we haven't copied any of it to dst yet.
		if m.config.ProxyProtocol {
			if err := writeProxyHeader(dst, conn); err != nil {
				log.Printf("[sentinel] proxy-proto: %v", err)
				return
			}
		}

		done := make(chan struct{}, 2)
		go func() { io.Copy(dst, peekedConn); done <- struct{}{} }()
		go func() { io.Copy(peekedConn, dst); done <- struct{}{} }()
		<-done
	}
}

// writeProxyHeader writes a PROXY v2 header to dst describing the client TCP
// connection conn. Returns an error if either address is missing or the write
// fails. Non-TCP addresses are skipped silently — without addresses we can't
// build a meaningful header, but failing the connection would be worse than
// degrading to the legacy "sentinel-as-client" behavior.
func writeProxyHeader(dst io.Writer, conn net.Conn) error {
	src, _ := conn.RemoteAddr().(*net.TCPAddr)
	dstAddr, _ := conn.LocalAddr().(*net.TCPAddr)
	if src == nil || dstAddr == nil {
		return nil
	}
	if _, err := WriteProxyV2(dst, src, dstAddr); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	return nil
}

// setHTTPSMaintenanceHandler sets the dispatch handler to serve maintenance TLS page.
func (m *Manager) setHTTPSMaintenanceHandler() {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if m.certStore != nil {
		tlsCfg.GetCertificate = m.certStore.GetCertificate
	} else {
		cert, err := generateSelfSignedCert()
		if err == nil {
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
	}

	handler := maintenanceHandler()

	m.httpsDispatch.SetHandler(func(conn net.Conn) {
		tlsConn := tls.Server(conn, tlsCfg)
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		// Serve one HTTP request over the TLS connection
		http.Serve(&singleConnListener{conn: tlsConn}, handler)
	})
	log.Printf("[sentinel] maintenance HTTPS handler set on ConnMux")
}

// singleConnListener is a net.Listener that serves exactly one connection.
type singleConnListener struct {
	conn net.Conn
	done bool
}

func (sl *singleConnListener) Accept() (net.Conn, error) {
	if sl.done {
		return nil, net.ErrClosed
	}
	sl.done = true
	return sl.conn, nil
}
func (sl *singleConnListener) Close() error   { return nil }
func (sl *singleConnListener) Addr() net.Addr { return sl.conn.LocalAddr() }

func startMaintenanceHTTPOnly(httpPort int, manager *Manager) (stop func(), err error) {
	httpSrv := NewMaintenanceServer(httpPort, manager)

	go func() {
		log.Printf("[sentinel] maintenance HTTP server listening on :%d", httpPort)
		if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("[sentinel] maintenance HTTP server error: %v", err)
		}
	}()

	return func() {
		httpSrv.Close()
	}, nil
}

// handleEvent processes a VM lifecycle event from the GCP event watcher.
func (m *Manager) handleEvent(ctx context.Context, event VMEvent) {
	gcpBackend := m.backends.Get("gcp")

	switch event.Type {
	case EventPreempted:
		m.preemptCount++
		m.lastPreemption = event.Timestamp
		log.Printf("[sentinel] EVENT: PREEMPTION detected at %s (total: %d) — %s",
			event.Timestamp.Format(time.RFC3339), m.preemptCount, event.Detail)

		if gcpBackend != nil {
			gcpBackend.Healthy = false
			gcpBackend.healthyCount = 0
			gcpBackend.unhealthyCount = 0
		}

		// In hybrid mode: failover to tunnel if available
		m.mu.RLock()
		isPrimary := m.primary == gcpBackend
		m.mu.RUnlock()

		if isPrimary && m.currentState() == StateProxy {
			m.failoverPrimary(ctx, gcpBackend)
		}

		// Try to restart the GCP VM
		if gcpBackend != nil && gcpBackend.Provider != nil {
			m.diagnoseAndRecover(ctx, gcpBackend)
		}

	case EventStopped, EventTerminated:
		log.Printf("[sentinel] EVENT: VM %s at %s — %s", event.Type, event.Timestamp.Format(time.RFC3339), event.Detail)
		if gcpBackend != nil {
			gcpBackend.Healthy = false
			gcpBackend.healthyCount = 0

			m.mu.RLock()
			isPrimary := m.primary == gcpBackend
			m.mu.RUnlock()

			if isPrimary && m.currentState() == StateProxy {
				m.failoverPrimary(ctx, gcpBackend)
			}
			if gcpBackend.Provider != nil {
				m.diagnoseAndRecover(ctx, gcpBackend)
			}
		}

	case EventStarted:
		log.Printf("[sentinel] EVENT: VM started at %s — %s", event.Timestamp.Format(time.RFC3339), event.Detail)
	}
}

func (m *Manager) checkRecoveryTimeout() {
	if m.config.RecoveryTimeout <= 0 || m.outageStart.IsZero() {
		return
	}
	elapsed := time.Since(m.outageStart)
	if elapsed > m.config.RecoveryTimeout {
		log.Printf("[sentinel] WARNING: recovery has taken %s (threshold: %s) — manual intervention may be needed",
			elapsed.Round(time.Second), m.config.RecoveryTimeout)
	}
}

func (m *Manager) diagnoseAndRecover(ctx context.Context, b *Backend) {
	if b.Provider == nil {
		return
	}

	status, err := b.Provider.GetInstanceStatus(ctx)
	if err != nil {
		log.Printf("[sentinel] failed to get status for %s: %v", b.ID, err)
		return
	}

	log.Printf("[sentinel] backend %s status: %s", b.ID, status)

	switch status {
	case StatusStopped, StatusTerminated:
		log.Printf("[sentinel] attempting to start %s...", b.ID)
		if err := b.Provider.StartInstance(ctx); err != nil {
			log.Printf("[sentinel] failed to start %s: %v", b.ID, err)
		} else {
			log.Printf("[sentinel] start command sent for %s", b.ID)
		}
	case StatusProvisioning:
		log.Printf("[sentinel] %s is provisioning...", b.ID)
	case StatusRunning:
		log.Printf("[sentinel] %s reports running but health check failed", b.ID)
	}
}

func (m *Manager) cleanup() {
	if m.stopMaintenance != nil {
		m.stopMaintenance()
		m.stopMaintenance = nil
	}
	disableForwarding()
	log.Printf("[sentinel] cleanup complete")
}

// --- Tunnel callbacks ---

// OnTunnelConnect is called when a remote spot connects via tunnel.
func (m *Manager) OnTunnelConnect(spot *TunnelSpot) {
	b := &Backend{
		ID:           "tunnel-" + spot.ID,
		Type:         BackendTunnel,
		IP:           spot.LocalIP,
		ExternalPort: spot.ExternalPort,
		Provider:     NewTunnelProvider(nil, spot.ID), // tunnel provider can't restart VMs
		Priority:     10, // lower priority than GCP for HTTP
		Pool:         spot.Pool,
	}
	m.backends.Add(b)

	log.Printf("[sentinel] tunnel connected: %s at %s (total backends: %d)", b.ID, b.IP, m.backends.Count())

	// If the tunnel handshake declared this spot is a primary (slice 6),
	// auto-register it in the primary registry pointing at its loopback
	// alias. The SNI router will then forward inbound traffic for the
	// primary's hostname/aliases through the tunnel.
	if spot.PublicHostname != "" && spot.PublicPort != 0 && m.primaries != nil {
		m.primaries.Register(Primary{
			Pool:        spot.Pool,
			Hostname:    spot.PublicHostname,
			Aliases:     spot.PublicAliases,
			BaseDomains: spot.PublicBaseDomains,
			IP:          spot.LocalIP,
			Port:        spot.PublicPort,
			BackendID:   b.ID,
		})
		log.Printf("[sentinel] tunnel-promoted primary: pool=%q hostname=%q aliases=%v base_domains=%v -> %s:%d",
			spot.Pool, spot.PublicHostname, spot.PublicAliases, spot.PublicBaseDomains, spot.LocalIP, spot.PublicPort)
	}

	// Start sync loops for this tunnel backend
	ctx := context.Background()
	m.startSyncLoops(ctx, b)

	// Health check loop will pick it up and switch to proxy if needed
}

// OnTunnelDisconnect is called when a remote spot disconnects.
func (m *Manager) OnTunnelDisconnect(spot *TunnelSpot) {
	backendID := "tunnel-" + spot.ID
	if m.primaries != nil {
		if n := m.primaries.UnregisterByBackendID(backendID); n > 0 {
			log.Printf("[sentinel] removed %d primary registration(s) for disconnected tunnel %s", n, backendID)
		}
	}
	removed := m.backends.Remove(backendID)
	if removed == nil {
		return
	}

	log.Printf("[sentinel] tunnel disconnected: %s (remaining backends: %d)", backendID, m.backends.Count())

	// Remove this backend's users from sshpiper config
	m.keyStore.RemoveBackend(backendID)
	if err := m.keyStore.Apply(); err != nil {
		log.Printf("[sentinel] key apply after tunnel disconnect failed: %v", err)
	} else {
		m.keyStore.RestartSSHPiper()
	}

	// If this was the primary, failover
	m.mu.RLock()
	wasPrimary := m.primary == removed
	m.mu.RUnlock()

	if wasPrimary && m.currentState() == StateProxy {
		next := m.backends.SelectPrimary()
		if next != nil {
			log.Printf("[sentinel] failover after tunnel disconnect: → %s (%s)", next.ID, next.IP)
			if err := m.switchToProxy(next); err != nil {
				log.Printf("[sentinel] failover failed: %v", err)
			}
		} else {
			m.outageStart = time.Now()
			if err := m.switchToMaintenance(); err != nil {
				log.Printf("[sentinel] failed to switch to maintenance: %v", err)
			}
		}
	}
}

// --- Exported state getters ---

func (m *Manager) CurrentState() State  { return m.currentState() }
func (m *Manager) PreemptCount() int    { return m.preemptCount }
func (m *Manager) LastPreemption() time.Time { return m.lastPreemption }

// SpotIP returns the primary backend IP (backward compat).
func (m *Manager) SpotIP() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.primary != nil {
		return m.primary.IP
	}
	return ""
}

// Backends returns status info for all backends.
func (m *Manager) Backends() []*Backend {
	return m.backends.All()
}

func (m *Manager) OutageDuration() time.Duration {
	if m.currentState() != StateMaintenance || m.outageStart.IsZero() {
		return 0
	}
	return time.Since(m.outageStart)
}

// excludePort returns a copy of ports with the given port removed.
func excludePort(ports []int, exclude int) []int {
	result := make([]int, 0, len(ports))
	for _, p := range ports {
		if p != exclude {
			result = append(result, p)
		}
	}
	return result
}
