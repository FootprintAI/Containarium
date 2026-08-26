package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Tests for the TCP/UDP passthrough route methods added for #1550: until
// now AddPassthroughRoute/ListPassthroughRoutes/DeletePassthroughRoute had
// no client-layer caller at all, even though the RPCs and their REST
// mapping (grpc-gateway on /v1/network/passthrough[...]) already existed
// server-side.

func TestHTTPAddPassthroughRoute_Success(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"route": {
				"externalPort": 9443,
				"targetIp": "10.0.3.150",
				"targetPort": 50051,
				"protocol": "ROUTE_PROTOCOL_TCP",
				"active": true,
				"containerName": "alice-container"
			},
			"message": "Passthrough route added: tcp:9443 -> 10.0.3.150:50051 (will sync to iptables)"
		}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	route, err := c.AddPassthroughRoute(9443, 50051, "10.0.3.150", pb.RouteProtocol_ROUTE_PROTOCOL_TCP, "alice-container", "grpc mTLS")
	if err != nil {
		t.Fatalf("AddPassthroughRoute: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q; want POST", gotMethod)
	}
	if gotPath != "/v1/network/passthrough" {
		t.Errorf("path = %q; want /v1/network/passthrough", gotPath)
	}
	// JSON numbers decode as float64.
	if gotBody["external_port"] != float64(9443) {
		t.Errorf("external_port = %v; want 9443", gotBody["external_port"])
	}
	if gotBody["target_ip"] != "10.0.3.150" {
		t.Errorf("target_ip = %v; want 10.0.3.150", gotBody["target_ip"])
	}
	if gotBody["protocol"] != float64(pb.RouteProtocol_ROUTE_PROTOCOL_TCP) {
		t.Errorf("protocol = %v; want %v", gotBody["protocol"], pb.RouteProtocol_ROUTE_PROTOCOL_TCP)
	}

	if route.GetExternalPort() != 9443 {
		t.Errorf("route.ExternalPort = %d; want 9443", route.GetExternalPort())
	}
	if route.GetTargetIp() != "10.0.3.150" {
		t.Errorf("route.TargetIp = %q; want 10.0.3.150", route.GetTargetIp())
	}
	if route.GetProtocol() != pb.RouteProtocol_ROUTE_PROTOCOL_TCP {
		t.Errorf("route.Protocol = %v; want TCP", route.GetProtocol())
	}
}

func TestHTTPAddPassthroughRoute_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"port already in use"}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	_, err = c.AddPassthroughRoute(9443, 50051, "10.0.3.150", pb.RouteProtocol_ROUTE_PROTOCOL_TCP, "", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestHTTPListPassthroughRoutes(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"routes": [
				{
					"externalPort": 9443,
					"targetIp": "10.0.3.150",
					"targetPort": 50051,
					"protocol": "ROUTE_PROTOCOL_TCP",
					"active": true,
					"containerName": "alice-container"
				}
			],
			"totalCount": 1
		}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	routes, total, err := c.ListPassthroughRoutes()
	if err != nil {
		t.Fatalf("ListPassthroughRoutes: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q; want GET", gotMethod)
	}
	if gotPath != "/v1/network/passthrough" {
		t.Errorf("path = %q; want /v1/network/passthrough", gotPath)
	}
	if total != 1 {
		t.Errorf("total = %d; want 1", total)
	}
	if len(routes) != 1 || routes[0].GetExternalPort() != 9443 {
		t.Fatalf("routes = %+v; want one route with externalPort 9443", routes)
	}
}

func TestHTTPDeletePassthroughRoute(t *testing.T) {
	var gotPath, gotMethod, gotProtocol string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotProtocol = r.URL.Query().Get("protocol")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"Passthrough route removed: tcp:9443 (will sync to iptables)"}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if err := c.DeletePassthroughRoute(9443, pb.RouteProtocol_ROUTE_PROTOCOL_TCP); err != nil {
		t.Fatalf("DeletePassthroughRoute: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", gotMethod)
	}
	if gotPath != "/v1/network/passthrough/9443" {
		t.Errorf("path = %q; want /v1/network/passthrough/9443", gotPath)
	}
	if gotProtocol != "ROUTE_PROTOCOL_TCP" {
		t.Errorf("protocol query = %q; want ROUTE_PROTOCOL_TCP", gotProtocol)
	}
}

func TestHTTPDeletePassthroughRoute_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	err = c.DeletePassthroughRoute(9443, pb.RouteProtocol_ROUTE_PROTOCOL_TCP)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
