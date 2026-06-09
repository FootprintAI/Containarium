// Package wakeproxy implements the sentinel-side ssh-wake-proxy (#539,
// wake-on-SSH). sshpiper's generated config points each user's upstream
// at 127.0.0.1:<wakePort> instead of the box directly; this proxy
// listens there and, on each inbound connection, ensures the box's sshd
// is up — waking a slept box via the daemon's HMAC /ssh-wake endpoint —
// then splices the TCP stream to the real box sshd. It is the SSH
// analogue of the wake-on-HTTP proxy (internal/wake): sshpiper keeps
// doing authorized_keys auth and per-user routing untouched.
package wakeproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// logf emits a tagged log line. Kept tiny so the proxy stays dependency-light.
func logf(format string, args ...interface{}) {
	log.Printf("[ssh-wake-proxy] "+format, args...)
}

// Route describes how to reach (and wake) one box. sshpiper dials
// 127.0.0.1:WakePort; the proxy wakes BackendIP via the daemon at
// BackendHTTPPort then splices to BackendIP:SSHPort.
type Route struct {
	Username        string `json:"username"`
	WakePort        int    `json:"wake_port"`
	BackendIP       string `json:"backend_ip"`
	SSHPort         int    `json:"ssh_port"`
	BackendHTTPPort int    `json:"backend_http_port"`
}

// RouteFile is the on-disk format keysync writes (wake-routes.json).
type RouteFile struct {
	Routes []Route `json:"routes"`
}

// LoadRoutes reads and parses the wake-routes file. A missing file is
// not an error — it yields an empty set (the sentinel may start before
// keysync has written any users).
func LoadRoutes(path string) ([]Route, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-controlled config path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var rf RouteFile
	if err := json.Unmarshal(b, &rf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return rf.Routes, nil
}

// Proxy wakes-then-splices SSH connections for a single Route. The
// network seams (probe dial, upstream dial, wake HTTP client) are
// overridable for tests; production uses the defaults.
type Proxy struct {
	secret []byte

	// WakeTimeout bounds how long we wait for the box's sshd to accept
	// after the daemon reports the box ready (mirror wake-on-HTTP's 30s).
	WakeTimeout time.Duration
	// ProbeTimeout is the per-dial timeout for the "is sshd up?" check.
	ProbeTimeout time.Duration

	// HTTPClient calls the daemon's /ssh-wake. Defaults to a client whose
	// timeout covers the daemon's own wake budget plus slack.
	HTTPClient *http.Client
	// Dial opens the upstream SSH connection; defaults to net.DialTimeout.
	Dial func(network, addr string, timeout time.Duration) (net.Conn, error)
}

// New builds a Proxy with production defaults. secret is the shared
// CONTAINARIUM_SENTINEL_AUTH_SECRET used to sign /ssh-wake calls; an
// empty secret means calls go unsigned and the daemon will 401 (the
// fail-closed posture matches the other sentinel endpoints).
func New(secret []byte) *Proxy {
	p := &Proxy{
		secret:       secret,
		WakeTimeout:  30 * time.Second,
		ProbeTimeout: 500 * time.Millisecond,
	}
	p.HTTPClient = &http.Client{Timeout: p.WakeTimeout + 5*time.Second}
	p.Dial = net.DialTimeout
	return p
}

// Handle services one accepted client connection for route r: ensure the
// box's sshd is reachable (waking it if needed), then splice. It always
// closes client before returning.
func (p *Proxy) Handle(ctx context.Context, client net.Conn, r Route) {
	defer func() { _ = client.Close() }()

	upstream := net.JoinHostPort(r.BackendIP, strconv.Itoa(r.SSHPort))

	// Fast path: a running box answers immediately, so we add only a
	// single dial probe before splicing.
	if !p.portOpen(upstream) {
		if err := p.wake(ctx, r); err != nil {
			logf("wake %s: %v", r.Username, err)
			return
		}
		// The daemon probes the box's own IP:22; re-confirm the address
		// the sentinel actually splices to is accepting before we dial.
		if !p.waitOpen(ctx, upstream) {
			logf("wake %s: upstream %s not ready after wake", r.Username, upstream)
			return
		}
	}

	dst, err := p.Dial("tcp", upstream, p.ProbeTimeout+5*time.Second)
	if err != nil {
		logf("dial upstream %s for %s: %v", upstream, r.Username, err)
		return
	}
	defer func() { _ = dst.Close() }()

	splice(client, dst)
}

// wake POSTs the daemon's HMAC-signed /ssh-wake and returns nil once the
// daemon reports the box ready.
func (p *Proxy) wake(ctx context.Context, r Route) error {
	url := fmt.Sprintf("http://%s:%d/ssh-wake", r.BackendIP, r.BackendHTTPPort)
	body, _ := json.Marshal(map[string]string{"username": r.Username})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(p.secret) > 0 {
		auth.SignSentinelRequest(req, p.secret)
	}
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	var wr struct {
		Ready bool `json:"ready"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wr); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if !wr.Ready {
		return fmt.Errorf("box did not become ready")
	}
	return nil
}

// portOpen reports whether addr accepts a TCP connection right now.
func (p *Proxy) portOpen(addr string) bool {
	conn, err := p.Dial("tcp", addr, p.ProbeTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// waitOpen polls addr until it accepts or WakeTimeout elapses / ctx ends.
func (p *Proxy) waitOpen(ctx context.Context, addr string) bool {
	deadline := time.Now().Add(p.WakeTimeout)
	for time.Now().Before(deadline) {
		if p.portOpen(addr) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(250 * time.Millisecond):
		}
	}
	return false
}

// splice copies bytes bidirectionally until either side closes.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// Unblock the peer copy by half-closing where possible.
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}
