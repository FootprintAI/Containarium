package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
	var receivedPath string
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path

		// Parse request body
		json.NewDecoder(r.Body).Decode(&receivedBody)

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
	if receivedPath != expectedPath {
		t.Errorf("request path = %q, want %q", receivedPath, expectedPath)
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
	var receivedPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
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
	if receivedPath != expectedPath {
		t.Errorf("request path = %q, want %q", receivedPath, expectedPath)
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
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	pm := NewProxyManager(server.URL, "containarium.dev")

	// Should not return error for 404 (route might already be deleted)
	err := pm.RemoveRoute("nonexistent")
	if err != nil {
		t.Errorf("RemoveRoute() should not error on 404, got: %v", err)
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

		routes := []CaddyRoute{
			{
				ID: "testuser-app1",
				Match: []CaddyMatch{
					{Host: []string{"testuser-app1.containarium.dev"}},
				},
				Handle: []map[string]interface{}{
					{
						"handler": "reverse_proxy",
						"upstreams": []map[string]string{
							{"dial": "10.100.0.15:3000"},
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
