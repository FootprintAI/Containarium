package sentinel

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBYOCRouteRegisterHandler_SyncsFullSet(t *testing.T) {
	m := &Manager{byocRoutes: NewBYOCRouteRegistry(), byocRouteStorePath: t.TempDir() + "/byoc.json"}
	h := m.BYOCRouteRegisterHandler()

	// Non-POST rejected.
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodGet, "/sentinel/byoc-routes", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET code = %d, want 405", rr.Code)
	}

	// POST a full set → stored + persisted.
	body := `{"routes":[{"hostname":"x-acme.containarium.dev","backend_id":"tunnel-h1","port":8080}]}`
	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/sentinel/byoc-routes", strings.NewReader(body)))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("POST code = %d, want 204", rr.Code)
	}
	if got, ok := m.byocRoutes.Lookup("x-acme.containarium.dev"); !ok || got.Port != 8080 {
		t.Fatalf("route not stored: %+v ok=%v", got, ok)
	}

	// A second POST with a different set replaces the first (full-set sync).
	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/sentinel/byoc-routes",
		strings.NewReader(`{"routes":[{"hostname":"y.containarium.dev","backend_id":"tunnel-h2","port":9000}]}`)))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("second POST code = %d", rr.Code)
	}
	if _, ok := m.byocRoutes.Lookup("x-acme.containarium.dev"); ok {
		t.Fatal("full-set sync must drop the previous binding")
	}
	if _, ok := m.byocRoutes.Lookup("y.containarium.dev"); !ok {
		t.Fatal("full-set sync must store the new binding")
	}

	// Disabled sentinel (nil registry) → 501.
	rr = httptest.NewRecorder()
	(&Manager{}).BYOCRouteRegisterHandler()(rr, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("nil-registry code = %d, want 501", rr.Code)
	}
}

// TestServeBYOCIngress_TerminatesTLSAndProxiesOverTunnel drives the full path:
// a TLS client → serveBYOCIngress (terminates TLS with the cert store) →
// reverse-proxy → injected "tunnel" dial → a plaintext HTTP backend. Asserts
// the box sees the preserved Host header and the client gets the box's body.
func TestServeBYOCIngress_TerminatesTLSAndProxiesOverTunnel(t *testing.T) {
	// The "box" behind the tunnel: a plaintext HTTP server that echoes Host.
	var gotHost, gotSpotID string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		_, _ = io.WriteString(w, "hello from box")
	}))
	defer backend.Close()

	m := &Manager{certStore: NewCertStore(), byocRoutes: NewBYOCRouteRegistry()}
	m.byocDial = func(spotID string, port int) (net.Conn, error) {
		gotSpotID = spotID // must be "tunnel-" stripped
		return net.Dial("tcp", backend.Listener.Addr().String())
	}
	route := BYOCRoute{Hostname: "app-acme.containarium.dev", BackendID: "tunnel-h1", Port: 8080}

	clientConn, serverConn := net.Pipe()
	go m.serveBYOCIngress(serverConn, route)

	tlsClient := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true, // the cert store serves its self-signed fallback in this test
		ServerName:         route.Hostname,
	})
	defer func() { _ = tlsClient.Close() }()
	_ = tlsClient.SetDeadline(time.Now().Add(10 * time.Second))

	req, _ := http.NewRequest(http.MethodGet, "https://"+route.Hostname+"/path", nil)
	if err := req.Write(tlsClient); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK || string(b) != "hello from box" {
		t.Fatalf("resp = %d %q", resp.StatusCode, string(b))
	}
	if gotHost != route.Hostname {
		t.Fatalf("box saw Host = %q, want %q (Host must be preserved)", gotHost, route.Hostname)
	}
	if gotSpotID != "h1" {
		t.Fatalf("dial spotID = %q, want %q (tunnel- prefix stripped)", gotSpotID, "h1")
	}
}
