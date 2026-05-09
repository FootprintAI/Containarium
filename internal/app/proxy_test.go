package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeCaddy is a minimal stand-in for the Caddy admin API that simulates the
// real semantics: GET on a config sub-path returns that sub-tree, POST /load
// atomically replaces the whole config. This is what the manager's
// getFullConfig + loadConfig path expects, and lets tests catch bugs that
// only show up under real /load semantics (vs. naive PATCH-replace).
type fakeCaddy struct {
	config map[string]interface{}
	loads  int
}

func newFakeCaddy(initial map[string]interface{}) *httptest.Server {
	fc := &fakeCaddy{config: initial}
	mux := http.NewServeMux()
	mux.HandleFunc("/config/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/config/")
		path = strings.TrimSuffix(path, "/")
		if path == "" {
			_ = json.NewEncoder(w).Encode(fc.config)
			return
		}
		var node interface{} = fc.config
		for _, p := range strings.Split(path, "/") {
			m, ok := node.(map[string]interface{})
			if !ok {
				http.Error(w, "null", http.StatusNotFound)
				return
			}
			node = m[p]
		}
		_ = json.NewEncoder(w).Encode(node)
	})
	mux.HandleFunc("/load", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var newCfg map[string]interface{}
		if err := json.Unmarshal(body, &newCfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fc.config = newCfg
		fc.loads++
		w.WriteHeader(http.StatusOK)
	})
	return httptest.NewServer(mux)
}

func TestNewProxyManager(t *testing.T) {
	pm := NewProxyManager("http://localhost:2019", "containarium.dev")

	if pm.caddyAdminURL != "http://localhost:2019" {
		t.Errorf("caddyAdminURL = %q, want %q", pm.caddyAdminURL, "http://localhost:2019")
	}

	if pm.baseDomain != "containarium.dev" {
		t.Errorf("baseDomain = %q, want %q", pm.baseDomain, "containarium.dev")
	}

	if pm.serverName != DefaultCaddyServerName {
		t.Errorf("serverName = %q, want %q", pm.serverName, DefaultCaddyServerName)
	}
}

func TestProxyManager_SetServerName(t *testing.T) {
	pm := NewProxyManager("http://localhost:2019", "containarium.dev")

	pm.SetServerName("custom-server")

	if pm.serverName != "custom-server" {
		t.Errorf("serverName = %q, want %q", pm.serverName, "custom-server")
	}
}

func TestProxyManager_AddRoute(t *testing.T) {
	// Create test server
	var routePath string
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle route addition
		if r.URL.Path == "/config/apps/http/servers/srv0/routes" && r.Method == "POST" {
			routePath = r.URL.Path
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.WriteHeader(http.StatusOK)
			return
		}
		// Handle TLS provisioning requests (just return OK)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "containarium.dev")

	err := pm.AddRoute("testuser-myapp", "10.100.0.15", 3000)
	if err != nil {
		t.Fatalf("AddRoute() error = %v", err)
	}

	// Verify the path includes the server name
	expectedPath := "/config/apps/http/servers/srv0/routes"
	if routePath != expectedPath {
		t.Errorf("request path = %q, want %q", routePath, expectedPath)
	}

	// Verify the route ID
	if id, ok := receivedBody["@id"].(string); !ok || id != "testuser-myapp" {
		t.Errorf("route @id = %v, want %q", receivedBody["@id"], "testuser-myapp")
	}

	// Verify host match
	if matches, ok := receivedBody["match"].([]interface{}); ok && len(matches) > 0 {
		match := matches[0].(map[string]interface{})
		if hosts, ok := match["host"].([]interface{}); ok && len(hosts) > 0 {
			if hosts[0] != "testuser-myapp.containarium.dev" {
				t.Errorf("host = %v, want %q", hosts[0], "testuser-myapp.containarium.dev")
			}
		}
	}
}

func TestProxyManager_AddRoute_CustomServerName(t *testing.T) {
	var routePath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture route addition path
		if r.URL.Path == "/config/apps/http/servers/main/routes" && r.Method == "POST" {
			routePath = r.URL.Path
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "containarium.dev")
	pm.SetServerName("main")

	err := pm.AddRoute("testuser-myapp", "10.100.0.15", 3000)
	if err != nil {
		t.Fatalf("AddRoute() error = %v", err)
	}

	// Verify the path uses the custom server name
	expectedPath := "/config/apps/http/servers/main/routes"
	if routePath != expectedPath {
		t.Errorf("request path = %q, want %q", routePath, expectedPath)
	}
}

func TestProxyManager_RemoveRoute(t *testing.T) {
	var receivedPath string
	var receivedMethod string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "containarium.dev")

	err := pm.RemoveRoute("testuser-myapp")
	if err != nil {
		t.Fatalf("RemoveRoute() error = %v", err)
	}

	if receivedMethod != "DELETE" {
		t.Errorf("method = %q, want %q", receivedMethod, "DELETE")
	}

	expectedPath := "/id/testuser-myapp"
	if receivedPath != expectedPath {
		t.Errorf("request path = %q, want %q", receivedPath, expectedPath)
	}
}

func TestProxyManager_RemoveRoute_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For DELETE by ID, return 404
		if r.Method == "DELETE" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// For GET routes (fallback), return empty list
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("[]"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "containarium.dev")

	// Should not return error when route doesn't exist
	err := pm.RemoveRoute("nonexistent")
	if err != nil {
		t.Errorf("RemoveRoute() should not error when route not found, got: %v", err)
	}
}

func TestProxyManager_AddRoute_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "containarium.dev")

	err := pm.AddRoute("testuser-myapp", "10.100.0.15", 3000)
	if err == nil {
		t.Error("AddRoute() expected error for 500 response")
	}
}

func TestProxyManager_ListRoutes(t *testing.T) {
	var receivedPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path

		routes := []caddyRouteJSON{
			{
				ID: "testuser-app1",
				Match: []CaddyMatchTyped{
					{Host: []string{"testuser-app1.containarium.dev"}},
				},
				Handle: []CaddyReverseProxyHandler{
					{
						Handler: "reverse_proxy",
						Upstreams: []CaddyUpstreamTyped{
							{Dial: "10.100.0.15:3000"},
						},
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(routes)
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "containarium.dev")

	routes, err := pm.ListRoutes()
	if err != nil {
		t.Fatalf("ListRoutes() error = %v", err)
	}

	// Verify the path includes the server name
	expectedPath := "/config/apps/http/servers/srv0/routes"
	if receivedPath != expectedPath {
		t.Errorf("request path = %q, want %q", receivedPath, expectedPath)
	}

	if len(routes) != 1 {
		t.Fatalf("ListRoutes() returned %d routes, want 1", len(routes))
	}

	if routes[0].Subdomain != "testuser-app1" {
		t.Errorf("route subdomain = %q, want %q", routes[0].Subdomain, "testuser-app1")
	}

	if routes[0].FullDomain != "testuser-app1.containarium.dev" {
		t.Errorf("route full domain = %q, want %q", routes[0].FullDomain, "testuser-app1.containarium.dev")
	}
}

func TestDefaultCaddyServerName(t *testing.T) {
	if DefaultCaddyServerName != "srv0" {
		t.Errorf("DefaultCaddyServerName = %q, want %q", DefaultCaddyServerName, "srv0")
	}
}

// Tests for new route management functionality

func TestProxyManager_RemoveRoute_FullDomain(t *testing.T) {
	// Test that RemoveRoute correctly extracts subdomain from full domain
	var receivedPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "kafeido.app")

	// Pass full domain, should extract "test" as route ID
	err := pm.RemoveRoute("test.kafeido.app")
	if err != nil {
		t.Fatalf("RemoveRoute() error = %v", err)
	}

	// Should delete by ID "test" (not "test.kafeido.app")
	expectedPath := "/id/test"
	if receivedPath != expectedPath {
		t.Errorf("request path = %q, want %q", receivedPath, expectedPath)
	}
}

func TestProxyManager_RemoveRoute_SubdomainOnly(t *testing.T) {
	// Test that RemoveRoute works with just subdomain
	var receivedPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "kafeido.app")

	err := pm.RemoveRoute("myapp")
	if err != nil {
		t.Fatalf("RemoveRoute() error = %v", err)
	}

	expectedPath := "/id/myapp"
	if receivedPath != expectedPath {
		t.Errorf("request path = %q, want %q", receivedPath, expectedPath)
	}
}

func TestProxyManager_RemoveRoute_FallbackToIndex(t *testing.T) {
	// Test that RemoveRoute falls back to finding by domain when ID not found
	deleteByIDCalled := false
	listRoutesCalled := false
	deleteByIndexCalled := false
	var deleteIndexPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "DELETE" && r.URL.Path == "/id/test":
			// First attempt: delete by ID returns 404
			deleteByIDCalled = true
			w.WriteHeader(http.StatusNotFound)

		case r.Method == "GET" && r.URL.Path == "/config/apps/http/servers/srv0/routes":
			// List routes to find the one matching our domain
			listRoutesCalled = true
			routes := []map[string]interface{}{
				{
					"match": []map[string]interface{}{
						{"host": []string{"other.kafeido.app"}},
					},
				},
				{
					"match": []map[string]interface{}{
						{"host": []string{"test.kafeido.app"}},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(routes)

		case r.Method == "DELETE" && r.URL.Path == "/config/apps/http/servers/srv0/routes/1":
			// Delete by index (index 1 = test.kafeido.app)
			deleteByIndexCalled = true
			deleteIndexPath = r.URL.Path
			w.WriteHeader(http.StatusOK)

		default:
			t.Logf("Unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "kafeido.app")

	err := pm.RemoveRoute("test.kafeido.app")
	if err != nil {
		t.Fatalf("RemoveRoute() error = %v", err)
	}

	if !deleteByIDCalled {
		t.Error("expected delete by ID to be called first")
	}

	if !listRoutesCalled {
		t.Error("expected list routes to be called for fallback")
	}

	if !deleteByIndexCalled {
		t.Error("expected delete by index to be called as fallback")
	}

	expectedPath := "/config/apps/http/servers/srv0/routes/1"
	if deleteIndexPath != expectedPath {
		t.Errorf("delete index path = %q, want %q", deleteIndexPath, expectedPath)
	}
}

func TestProxyManager_AddRoute_FullDomain(t *testing.T) {
	// Test that AddRoute handles full domain without doubling base domain
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "kafeido.app")

	// Pass full domain - should NOT become "test.kafeido.app.kafeido.app"
	err := pm.AddRoute("test.kafeido.app", "10.0.3.136", 8080)
	if err != nil {
		t.Fatalf("AddRoute() error = %v", err)
	}

	// Verify the route ID is "test" (subdomain extracted)
	if id, ok := receivedBody["@id"].(string); !ok || id != "test" {
		t.Errorf("route @id = %v, want %q", receivedBody["@id"], "test")
	}

	// Verify host match is the full domain (not doubled)
	if matches, ok := receivedBody["match"].([]interface{}); ok && len(matches) > 0 {
		match := matches[0].(map[string]interface{})
		if hosts, ok := match["host"].([]interface{}); ok && len(hosts) > 0 {
			if hosts[0] != "test.kafeido.app" {
				t.Errorf("host = %v, want %q", hosts[0], "test.kafeido.app")
			}
		}
	}
}

func TestProxyManager_AddRoute_SubdomainOnly(t *testing.T) {
	// Test that AddRoute correctly appends base domain to subdomain
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "kafeido.app")

	// Pass subdomain only
	err := pm.AddRoute("myapp", "10.0.3.136", 8080)
	if err != nil {
		t.Fatalf("AddRoute() error = %v", err)
	}

	// Verify the route ID is the subdomain
	if id, ok := receivedBody["@id"].(string); !ok || id != "myapp" {
		t.Errorf("route @id = %v, want %q", receivedBody["@id"], "myapp")
	}

	// Verify host match includes base domain
	if matches, ok := receivedBody["match"].([]interface{}); ok && len(matches) > 0 {
		match := matches[0].(map[string]interface{})
		if hosts, ok := match["host"].([]interface{}); ok && len(hosts) > 0 {
			if hosts[0] != "myapp.kafeido.app" {
				t.Errorf("host = %v, want %q", hosts[0], "myapp.kafeido.app")
			}
		}
	}
}

func TestProxyManager_AddRoute_NoBaseDomain(t *testing.T) {
	// Test that AddRoute works without base domain configured
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "") // No base domain

	err := pm.AddRoute("custom.example.com", "10.0.3.136", 8080)
	if err != nil {
		t.Fatalf("AddRoute() error = %v", err)
	}

	// Verify the full domain is used as-is
	if matches, ok := receivedBody["match"].([]interface{}); ok && len(matches) > 0 {
		match := matches[0].(map[string]interface{})
		if hosts, ok := match["host"].([]interface{}); ok && len(hosts) > 0 {
			if hosts[0] != "custom.example.com" {
				t.Errorf("host = %v, want %q", hosts[0], "custom.example.com")
			}
		}
	}
}

func TestProxyManager_UpdateRoute(t *testing.T) {
	// Test UpdateRoute (removes then adds)
	deleteCalled := false
	addCalled := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			deleteCalled = true
			w.WriteHeader(http.StatusOK)
		} else if r.Method == "POST" {
			addCalled = true
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "kafeido.app")

	err := pm.UpdateRoute("test", "10.0.3.140", 9000)
	if err != nil {
		t.Fatalf("UpdateRoute() error = %v", err)
	}

	if !deleteCalled {
		t.Error("expected delete to be called")
	}

	if !addCalled {
		t.Error("expected add to be called")
	}
}

func TestProxyManager_ListRoutes_Empty(t *testing.T) {
	// Test ListRoutes with no routes configured
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "kafeido.app")

	routes, err := pm.ListRoutes()
	if err != nil {
		t.Fatalf("ListRoutes() error = %v", err)
	}

	if len(routes) != 0 {
		t.Errorf("ListRoutes() returned %d routes, want 0", len(routes))
	}
}

func TestProxyManager_ListRoutes_BadRequest(t *testing.T) {
	// Test ListRoutes when Caddy returns 400 (no http app configured)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid traversal path"))
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "kafeido.app")

	routes, err := pm.ListRoutes()
	if err != nil {
		t.Fatalf("ListRoutes() should return empty on 400, got error: %v", err)
	}

	if len(routes) != 0 {
		t.Errorf("ListRoutes() returned %d routes, want 0 on 400 response", len(routes))
	}
}

// TestProxyManager_EnableProxyProtocol_PreservesOtherFields is a regression
// test for the prod-broke-everything bug: a naive `PATCH /config/.../srv0`
// REPLACES the resource at that path, wiping listen/routes/etc. The fix is to
// read the full config, set only the two new fields on the server map, and
// atomically /load. The fake Caddy here mirrors the real semantics — its
// /load endpoint accepts the entire config and is the only way to mutate
// state — so a regression to PATCH-replace would surface as missing fields.
func TestProxyManager_EnableProxyProtocol_PreservesOtherFields(t *testing.T) {
	initial := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"listen": []interface{}{":80", ":443"},
						"routes": []interface{}{
							map[string]interface{}{
								"@id":    "wordpress.kafeido.app",
								"match":  []interface{}{map[string]interface{}{"host": []interface{}{"wordpress.kafeido.app"}}},
								"handle": []interface{}{map[string]interface{}{"handler": "reverse_proxy", "upstreams": []interface{}{map[string]interface{}{"dial": "10.0.3.53:8888"}}}},
							},
						},
						"automatic_https": map[string]interface{}{"disable_redirects": false},
					},
				},
			},
		},
	}
	srv := newFakeCaddy(initial)
	defer srv.Close()

	pm := NewProxyManager(srv.URL, "kafeido.app")
	if err := pm.EnableProxyProtocol([]string{"10.130.0.13/32", "127.0.0.0/8"}); err != nil {
		t.Fatalf("EnableProxyProtocol err = %v", err)
	}

	resp, err := http.Get(srv.URL + "/config/")
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	defer resp.Body.Close()
	var cfg map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&cfg)

	srv0 := cfg["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})["srv0"].(map[string]interface{})

	// New fields are present and well-shaped.
	wrappers, ok := srv0["listener_wrappers"].([]interface{})
	if !ok || len(wrappers) != 2 {
		t.Fatalf("listener_wrappers shape wrong: %v", srv0["listener_wrappers"])
	}
	if w0 := wrappers[0].(map[string]interface{}); w0["wrapper"] != "proxy_protocol" {
		t.Errorf("first wrapper = %v, want proxy_protocol", w0["wrapper"])
	}
	if w1 := wrappers[1].(map[string]interface{}); w1["wrapper"] != "tls" {
		t.Errorf("second wrapper = %v, want tls", w1["wrapper"])
	}
	tp, ok := srv0["trusted_proxies"].(map[string]interface{})
	if !ok || tp["source"] != "static" {
		t.Fatalf("trusted_proxies wrong: %v", srv0["trusted_proxies"])
	}
	tpRanges, _ := tp["ranges"].([]interface{})
	if len(tpRanges) != 2 || tpRanges[0] != "10.130.0.13/32" {
		t.Errorf("trusted_proxies.ranges = %v, want [10.130.0.13/32 127.0.0.0/8]", tpRanges)
	}

	// THE REGRESSION CHECK — every pre-existing field must still be present.
	listen, ok := srv0["listen"].([]interface{})
	if !ok || len(listen) != 2 || listen[0] != ":80" || listen[1] != ":443" {
		t.Fatalf("REGRESSION: listen was clobbered, got %v (want [:80 :443])", srv0["listen"])
	}
	routes, ok := srv0["routes"].([]interface{})
	if !ok || len(routes) != 1 {
		t.Fatalf("REGRESSION: routes was clobbered, got %v", srv0["routes"])
	}
	if _, ok := srv0["automatic_https"]; !ok {
		t.Errorf("REGRESSION: automatic_https field was wiped")
	}
}

func TestProxyManager_EnableProxyProtocol_RefusesEmpty(t *testing.T) {
	pm := NewProxyManager("http://unreachable", "kafeido.app")
	if err := pm.EnableProxyProtocol(nil); err == nil {
		t.Errorf("expected error on empty CIDRs, got nil")
	}
}

func TestProxyManager_EnableProxyProtocol_RefusesWildcard(t *testing.T) {
	pm := NewProxyManager("http://unreachable", "kafeido.app")
	if err := pm.EnableProxyProtocol([]string{"0.0.0.0/0"}); err == nil {
		t.Errorf("expected error on wildcard CIDR, got nil")
	}
	if err := pm.EnableProxyProtocol([]string{"10.0.0.0/8", "::/0"}); err == nil {
		t.Errorf("expected error on IPv6 wildcard CIDR, got nil")
	}
}
