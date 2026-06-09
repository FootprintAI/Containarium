package cmd

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/wakeproxy"
	"github.com/spf13/cobra"
)

var (
	sshWakeProxyRoutes   string
	sshWakeProxyHost     string
	sshWakeProxyInterval time.Duration
)

// sshWakeProxyCmd runs the sentinel-side wake-on-SSH proxy (#539). It's a
// subcommand of the containarium binary (already present on the sentinel)
// rather than a separate binary, so deployment ships nothing extra — the
// startup script just runs it as its own systemd service alongside
// `containarium sentinel`.
var sshWakeProxyCmd = &cobra.Command{
	Use:   "ssh-wake-proxy",
	Short: "Sentinel-side wake-on-SSH proxy (#539)",
	Long: `Run the wake-on-SSH proxy on the sentinel.

sshpiper's generated config (keysync) points each user's upstream at
127.0.0.1:<wakePort> instead of the box directly. This process listens on
those ports and, per inbound SSH connection, ensures the box's sshd is up
— waking a slept box via the daemon's HMAC-signed /ssh-wake endpoint —
then splices the TCP stream to the real box sshd. sshpiper's authorized_keys
auth and per-user routing are untouched. It re-reads the wake-routes file
periodically so newly-claimed users become reachable without a restart.

The shared HMAC secret is read from CONTAINARIUM_SENTINEL_AUTH_SECRET (the
same secret the sentinel uses for /authorized-keys); without it the daemon
rejects wake calls with 401.`,
	RunE: runSSHWakeProxy,
}

func init() {
	rootCmd.AddCommand(sshWakeProxyCmd)
	sshWakeProxyCmd.Flags().StringVar(&sshWakeProxyRoutes, "routes", "/etc/sshpiper/wake-routes.json", "path to the wake-routes JSON written by keysync")
	sshWakeProxyCmd.Flags().StringVar(&sshWakeProxyHost, "host", "127.0.0.1", "host to bind the per-box wake listeners on")
	sshWakeProxyCmd.Flags().DurationVar(&sshWakeProxyInterval, "reload-interval", 5*time.Second, "how often to re-read the routes file")
}

func runSSHWakeProxy(cmd *cobra.Command, args []string) error {
	secret := []byte(os.Getenv("CONTAINARIUM_SENTINEL_AUTH_SECRET"))
	if len(secret) == 0 {
		log.Printf("[ssh-wake-proxy] WARNING: CONTAINARIUM_SENTINEL_AUTH_SECRET is unset — /ssh-wake calls will be unsigned and the daemon will reject them (401)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	m := &wakeListenerSet{
		proxy:     wakeproxy.New(secret),
		host:      sshWakeProxyHost,
		ctx:       ctx,
		listeners: make(map[int]net.Listener),
		routes:    make(map[int]wakeproxy.Route),
	}

	m.reload(sshWakeProxyRoutes)
	ticker := time.NewTicker(sshWakeProxyInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("[ssh-wake-proxy] shutting down")
			m.closeAll()
			return nil
		case <-ticker.C:
			m.reload(sshWakeProxyRoutes)
		}
	}
}

// wakeListenerSet owns one listener per wakePort and reconciles the set
// against the routes file on each reload.
type wakeListenerSet struct {
	proxy *wakeproxy.Proxy
	host  string
	ctx   context.Context

	mu        sync.RWMutex
	listeners map[int]net.Listener
	routes    map[int]wakeproxy.Route
}

func (m *wakeListenerSet) reload(path string) {
	routes, err := wakeproxy.LoadRoutes(path)
	if err != nil {
		log.Printf("[ssh-wake-proxy] load routes: %v (keeping current set)", err)
		return
	}
	want := make(map[int]wakeproxy.Route, len(routes))
	for _, r := range routes {
		if r.WakePort <= 0 || r.BackendIP == "" {
			continue
		}
		want[r.WakePort] = r
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for port, ln := range m.listeners {
		if _, ok := want[port]; !ok {
			_ = ln.Close()
			delete(m.listeners, port)
			delete(m.routes, port)
		}
	}
	for port, r := range want {
		m.routes[port] = r
		if _, ok := m.listeners[port]; ok {
			continue
		}
		addr := net.JoinHostPort(m.host, strconv.Itoa(port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("[ssh-wake-proxy] listen %s for %s: %v", addr, r.Username, err)
			continue
		}
		m.listeners[port] = ln
		go m.accept(port, ln)
	}
}

// accept serves a single listener until it's closed, looking up the
// current route for its port per connection so a reload that re-points
// the port takes effect for the next connection.
func (m *wakeListenerSet) accept(port int, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed by a reload, or fatal
		}
		m.mu.RLock()
		r, ok := m.routes[port]
		m.mu.RUnlock()
		if !ok {
			_ = conn.Close()
			continue
		}
		go m.proxy.Handle(m.ctx, conn, r)
	}
}

func (m *wakeListenerSet) closeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for port, ln := range m.listeners {
		_ = ln.Close()
		delete(m.listeners, port)
	}
}
