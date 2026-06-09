package wakeproxy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// echoServer accepts one connection on ln and echoes bytes back until EOF.
func echoServer(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	u := strings.TrimPrefix(rawURL, "http://")
	host, portStr, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatalf("split %s: %v", rawURL, err)
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// roundTrip writes a probe string through the proxy and asserts the echo.
func roundTrip(t *testing.T, p *Proxy, r Route) {
	t.Helper()
	clientSide, proxySide := net.Pipe()
	done := make(chan struct{})
	go func() {
		p.Handle(context.Background(), proxySide, r)
		close(done)
	}()

	msg := []byte("wake-on-ssh-hello")
	go func() { _, _ = clientSide.Write(msg) }()
	buf := make([]byte, len(msg))
	_ = clientSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(clientSide, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return after client close")
	}
}

func TestProxy_FastPath_NoWakeWhenUp(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	echoServer(t, backend)
	backendPort := backend.Addr().(*net.TCPAddr).Port

	// A daemon that fails the test if it's ever called — the box is up,
	// so the proxy must take the fast path and never wake.
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("daemon /ssh-wake called for an already-running box")
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer daemon.Close()
	_, dPort := hostPort(t, daemon.URL)

	p := New(nil)
	roundTrip(t, p, Route{Username: "u", BackendIP: "127.0.0.1", SSHPort: backendPort, BackendHTTPPort: dPort})
}

func TestProxy_WakesSleptBoxThenSplices(t *testing.T) {
	// Reserve the backend port but DON'T listen — the box is "slept".
	backendPort := freePort(t)
	secret := []byte("0123456789abcdef0123456789abcdef")

	var signed bool
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Containarium-Sentinel-Sig") != "" {
			signed = true
		}
		// "Start" the box: bring up the echo backend on its known port.
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(backendPort)))
		if err != nil {
			http.Error(w, "start failed", http.StatusInternalServerError)
			return
		}
		echoServer(t, ln)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ready": true})
	}))
	defer daemon.Close()
	_, dPort := hostPort(t, daemon.URL)

	p := New(secret)
	p.WakeTimeout = 3 * time.Second
	roundTrip(t, p, Route{Username: "u", BackendIP: "127.0.0.1", SSHPort: backendPort, BackendHTTPPort: dPort})

	if !signed {
		t.Error("wake request was not HMAC-signed")
	}
}

func TestProxy_WakeNotReady_ClosesClient(t *testing.T) {
	backendPort := freePort(t) // never comes up
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ready": false})
	}))
	defer daemon.Close()
	_, dPort := hostPort(t, daemon.URL)

	p := New(nil)
	clientSide, proxySide := net.Pipe()
	done := make(chan struct{})
	go func() {
		p.Handle(context.Background(), proxySide, Route{Username: "u", BackendIP: "127.0.0.1", SSHPort: backendPort, BackendHTTPPort: dPort})
		close(done)
	}()

	// Client read should hit EOF (proxy closed the conn after a failed wake).
	_ = clientSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := clientSide.Read(buf); err == nil {
		t.Fatal("expected client conn to be closed after failed wake")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return after failed wake")
	}
}

func TestLoadRoutes(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/wake-routes.json"

	// Missing file → empty, no error.
	if got, err := LoadRoutes(path); err != nil || len(got) != 0 {
		t.Fatalf("missing file: got %v, %v", got, err)
	}

	rf := RouteFile{Routes: []Route{{Username: "alice", WakePort: 40000, BackendIP: "10.0.0.5", SSHPort: 22, BackendHTTPPort: 8080}}}
	b, _ := json.Marshal(rf)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadRoutes(path)
	if err != nil || len(got) != 1 || got[0].Username != "alice" || got[0].WakePort != 40000 {
		t.Fatalf("LoadRoutes = %#v, %v", got, err)
	}
}

// ensure the auth import is exercised (signing path) so a refactor that
// drops it is caught by the build, not just at runtime.
var _ = auth.SignSentinelRequest
