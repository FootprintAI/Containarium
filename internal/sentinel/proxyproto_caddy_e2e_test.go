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

// waitForCaddyReady polls until BOTH the admin endpoint and the HTTPS
// listener are accepting connections, or the context is cancelled.
//
// On CI runners with cold caches, Caddy can take several seconds to
// provision its internal CA cert and finish wiring up the HTTPS server even
// after the admin API responds. So both probes are required: admin is the
// "config loaded" signal, and the TCP probe on httpsPort is the "ready to
// terminate TLS" signal.
func waitForCaddyReady(ctx context.Context, adminPort, httpsPort int) error {
	adminURL := fmt.Sprintf("http://127.0.0.1:%d/config/", adminPort)
	httpsAddr := fmt.Sprintf("127.0.0.1:%d", httpsPort)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()

	adminOK, httpsOK := false, false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("timeout waiting for caddy: admin=%v httpsListen=%v", adminOK, httpsOK)
		case <-tick.C:
			if !adminOK {
				if resp, err := http.Get(adminURL); err == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						adminOK = true
					}
				}
			}
			if !httpsOK {
				c, err := net.DialTimeout("tcp", httpsAddr, 200*time.Millisecond)
				if err == nil {
					c.Close()
					httpsOK = true
				}
			}
			if adminOK && httpsOK {
				return nil
			}
		}
	}
}

// testWriter adapts t.Logf so subprocess output appears in test logs.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("[caddy] %s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
