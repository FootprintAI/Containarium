//go:build proxyproto_real_caddy
// +build proxyproto_real_caddy

// This file is gated behind the proxyproto_real_caddy build tag because it
// shells out to a real `caddy` binary, which is heavy and not in the default
// CI image. Run it explicitly:
//
//	go test -tags=proxyproto_real_caddy -run TestProxyProtocolE2E_RealCaddy \
//	    -v ./internal/sentinel/...
//
// The test proves end-to-end that our PROXY v2 wire format is byte-compatible
// with Caddy's built-in `proxy_protocol` listener wrapper (Caddy 2.7+) — i.e.
// what the daemon actually runs in production. The companion test in
// proxyproto_e2e_test.go covers the same ground using pires/go-proxyproto as a
// stand-in parser; this one removes that one degree of separation by talking
// to a real Caddy.

package sentinel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyProtocolE2E_RealCaddy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-Caddy e2e in short mode")
	}
	if runtime.GOOS == "darwin" {
		t.Skip("requires Linux loopback (binding 127.0.0.42 needs lo aliases on darwin)")
	}
	caddyBin, err := exec.LookPath("caddy")
	if err != nil {
		t.Skip("caddy binary not in PATH; install via `xcaddy build` and rerun")
	}

	// ---------------------------------------------------------------
	// 1. Backend: in-process HTTP server that echoes X-Forwarded-For
	// ---------------------------------------------------------------

	echoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "x_forwarded_for=%s\n", r.Header.Get("X-Forwarded-For"))
		fmt.Fprintf(w, "remote_addr=%s\n", r.RemoteAddr)
	}))
	defer echoSrv.Close()
	echoPort := echoSrv.Listener.Addr().(*net.TCPAddr).Port

	// ---------------------------------------------------------------
	// 2. Generate a Caddy config with [proxy_protocol, tls] wrappers
	// ---------------------------------------------------------------

	caddyHTTPSPort := freePort(t)
	caddyAdminPort := freePort(t)

	storageDir := t.TempDir()
	cfg := fmt.Sprintf(`{
  "admin": {"listen": "127.0.0.1:%d"},
  "storage": {"module": "file_system", "root": %q},
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":%d"],
          "automatic_https": {"disable_redirects": true},
          "listener_wrappers": [
            {"wrapper": "proxy_protocol", "timeout": "5s", "allow": ["127.0.0.0/8"]},
            {"wrapper": "tls"}
          ],
          "trusted_proxies": {"source": "static", "ranges": ["127.0.0.0/8"]},
          "routes": [{
            "match": [{"host": ["localhost"]}],
            "handle": [{
              "handler": "reverse_proxy",
              "upstreams": [{"dial": "127.0.0.1:%d"}]
            }]
          }],
          "tls_connection_policies": [{}]
        }
      }
    },
    "tls": {
      "automation": {
        "policies": [{
          "subjects": ["localhost"],
          "issuers": [{"module": "internal"}]
        }]
      }
    }
  }
}`, caddyAdminPort, storageDir, caddyHTTPSPort, echoPort)

	cfgPath := filepath.Join(t.TempDir(), "caddy.json")
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfg), 0644))

	// ---------------------------------------------------------------
	// 3. Spawn Caddy as a subprocess
	// ---------------------------------------------------------------

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	caddyCmd := exec.CommandContext(ctx, caddyBin, "run", "--config", cfgPath)
	// Sandbox Caddy's filesystem effects to a tempdir so it doesn't write into
	// the user's ~/.local/share/caddy or try to install a CA cert system-wide.
	caddyHome := t.TempDir()
	caddyCmd.Env = append(os.Environ(),
		"XDG_DATA_HOME="+caddyHome,
		"XDG_CONFIG_HOME="+caddyHome,
		"HOME="+caddyHome,
	)
	caddyOut, err := caddyCmd.StderrPipe()
	require.NoError(t, err)
	caddyCmd.Stdout = caddyCmd.Stderr // unify
	require.NoError(t, caddyCmd.Start())

	// Stream Caddy logs for visibility on failure.
	go func() { _, _ = io.Copy(testWriter{t}, caddyOut) }()

	defer func() {
		_ = caddyCmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = caddyCmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = caddyCmd.Process.Kill()
			<-done
		}
	}()

	require.NoError(t, waitForCaddyReady(ctx, caddyAdminPort, caddyHTTPSPort), "caddy never became ready")

	// ---------------------------------------------------------------
	// 4. In-process relay: TCP forwarder that prepends our PROXY v2 header
	// ---------------------------------------------------------------

	relayLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer relayLn.Close()

	go runProxyProtoRelay(relayLn, fmt.Sprintf("127.0.0.1:%d", caddyHTTPSPort))

	// ---------------------------------------------------------------
	// 5. Drive a TLS request from a distinct loopback IP
	// ---------------------------------------------------------------

	clientIP := net.IPv4(127, 0, 0, 42)
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: clientIP, Port: 0},
		Timeout:   5 * time.Second,
	}
	rawConn, err := dialer.Dial("tcp", relayLn.Addr().String())
	require.NoError(t, err)
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
	})
	rawConn.SetDeadline(time.Now().Add(5 * time.Second))
	require.NoError(t, tlsConn.Handshake())

	_, err = fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)

	respBytes, err := io.ReadAll(tlsConn)
	require.NoError(t, err)
	resp := string(respBytes)
	t.Logf("[real-caddy] response:\n%s", resp)

	// ---------------------------------------------------------------
	// 6. The assertion
	// ---------------------------------------------------------------

	assert.Contains(t, resp, "x_forwarded_for=127.0.0.42",
		"real Caddy did not surface the relay-supplied client IP. "+
			"This means the wire format produced by WriteProxyV2 is incompatible with "+
			"caddy.listeners.proxy_protocol — fix the encoder before shipping.")
}

// runProxyProtoRelay is the in-test equivalent of the sentinel's HTTPS
// forwarding path: accept TCP, write a PROXY v2 header derived from the
// client connection's RemoteAddr/LocalAddr, then bidirectional pipe.
func runProxyProtoRelay(ln net.Listener, backend string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			up, err := net.Dial("tcp", backend)
			if err != nil {
				return
			}
			defer up.Close()
			src, _ := c.RemoteAddr().(*net.TCPAddr)
			dst, _ := c.LocalAddr().(*net.TCPAddr)
			if src != nil && dst != nil {
				if _, err := WriteProxyV2(up, src, dst); err != nil {
					return
				}
			}
			done := make(chan struct{}, 2)
			go func() { io.Copy(up, c); done <- struct{}{} }()
			go func() { io.Copy(c, up); done <- struct{}{} }()
			<-done
		}(c)
	}
}

// waitForCaddyReady polls until Caddy is fully ready to terminate
// requests through its proxy_protocol+tls listener, or the context is
// cancelled.
//
// History: an earlier version used a plain TCP-connect probe on httpsPort
// to signal "listener ready." That probe was a lie. Caddy's HTTPS
// listener accepts TCP connections the moment its kernel listen socket
// binds — well before the TLS automation has provisioned its internal
// CA and issued a cert for "localhost." Tests racing past that probe
// would then hit `tls: internal error` on handshake. ~10% of CI runs
// flaked this way until we replaced the TCP probe with a real
// end-to-end handshake.
//
// The current readiness probe:
//
//  1. Admin endpoint returns 200 — config has loaded.
//  2. A round-trip from a fresh TCP dial → PROXY v2 header →
//     TLS handshake to ServerName "localhost" succeeds. This proves
//     the listener_wrappers (proxy_protocol then tls) are wired up
//     AND the cert is provisioned and present in the TLS state machine.
//
// Both probes use a generous 45s deadline because cold-cache CI runners
// have been observed to take 8–15s on cert provisioning.
func waitForCaddyReady(ctx context.Context, adminPort, httpsPort int) error {
	adminURL := fmt.Sprintf("http://127.0.0.1:%d/config/", adminPort)
	httpsAddr := fmt.Sprintf("127.0.0.1:%d", httpsPort)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()

	adminOK, tlsOK := false, false
	var lastTLSErr error
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("timeout waiting for caddy: admin=%v tlsHandshake=%v lastTLSErr=%v",
				adminOK, tlsOK, lastTLSErr)
		case <-tick.C:
			if !adminOK {
				if resp, err := http.Get(adminURL); err == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						adminOK = true
					}
				}
			}
			if adminOK && !tlsOK {
				if err := probeCaddyTLS(httpsAddr); err == nil {
					tlsOK = true
				} else {
					lastTLSErr = err
				}
			}
			if adminOK && tlsOK {
				return nil
			}
		}
	}
}

// probeCaddyTLS performs one full PROXY-v2-then-TLS-handshake probe
// against Caddy's HTTPS listener. Returns nil on success, the underlying
// error on failure. Loopback-only (Caddy's listener_wrapper trusts
// 127.0.0.0/8 in the test config), with short per-probe deadlines so a
// stuck handshake doesn't burn the outer waitForCaddyReady budget.
func probeCaddyTLS(httpsAddr string) error {
	conn, err := net.DialTimeout("tcp", httpsAddr, 1*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	src := conn.LocalAddr().(*net.TCPAddr)
	dst := conn.RemoteAddr().(*net.TCPAddr)
	if _, err := WriteProxyV2(conn, src, dst); err != nil {
		return fmt.Errorf("proxy header: %w", err)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		// The probe is a liveness check, not a security check; the
		// internal CA's cert isn't in any trust store.
		InsecureSkipVerify: true, //nolint:gosec
		ServerName:         "localhost",
	})
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	_ = tlsConn.Close()
	return nil
}

// testWriter adapts t.Logf so subprocess output appears in test logs.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("[caddy] %s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
