package app

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestL4ProxyManager_EnableL4ProxyProtocol_NotActive: when L4 is not in the
// running config, the call must be a graceful no-op — RouteSyncJob will
// activate L4 later, and the daemon should be restarted to re-apply.
func TestL4ProxyManager_EnableL4ProxyProtocol_NotActive(t *testing.T) {
	srv := newFakeCaddy(map[string]interface{}{"apps": map[string]interface{}{}})
	defer srv.Close()
	m := NewL4ProxyManager(srv.URL)
	if err := m.EnableL4ProxyProtocol([]string{"10.130.0.13/32"}); err != nil {
		t.Fatalf("expected no-op when L4 inactive, got %v", err)
	}
}

// TestL4ProxyManager_EnableL4ProxyProtocol_WrapsRoutes asserts the verified-
// good pattern from sandbox tier 1: a single outer route whose handlers are
// (proxy_protocol, subroute), with the catchall inside the subroute tagged
// with proxy_protocol: "v2" for outbound emission to srv0. SNI passthrough
// routes are left untagged because gRPC backends typically don't speak
// PROXY.
func TestL4ProxyManager_EnableL4ProxyProtocol_WrapsRoutes(t *testing.T) {
	originalRoutes := []interface{}{
		// SNI route — should NOT get proxy_protocol: v2 (gRPC backend gets raw TLS).
		map[string]interface{}{
			"match": []interface{}{
				map[string]interface{}{"tls": map[string]interface{}{"sni": []interface{}{"grpc.kafeido.app"}}},
			},
			"handle": []interface{}{
				map[string]interface{}{"handler": "proxy", "upstreams": []interface{}{
					map[string]interface{}{"dial": []interface{}{"10.0.3.248:50051"}},
				}},
			},
		},
		// Catchall — SHOULD get proxy_protocol: v2 so srv0 sees the parsed source.
		map[string]interface{}{
			"handle": []interface{}{
				map[string]interface{}{"handler": "proxy", "upstreams": []interface{}{
					map[string]interface{}{"dial": []interface{}{"localhost:8443"}},
				}},
			},
		},
	}
	initial := map[string]interface{}{
		"apps": map[string]interface{}{
			"layer4": map[string]interface{}{
				"servers": map[string]interface{}{
					L4ServerName: map[string]interface{}{
						"listen": []interface{}{":443"},
						"routes": originalRoutes,
					},
				},
			},
		},
	}
	srv := newFakeCaddy(initial)
	defer srv.Close()

	m := NewL4ProxyManager(srv.URL)
	if err := m.EnableL4ProxyProtocol([]string{"10.130.0.13/32"}); err != nil {
		t.Fatalf("EnableL4ProxyProtocol err = %v", err)
	}

	resp, _ := http.Get(srv.URL + "/config/")
	defer resp.Body.Close()
	var cfg map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&cfg)
	srvCfg := cfg["apps"].(map[string]interface{})["layer4"].(map[string]interface{})["servers"].(map[string]interface{})[L4ServerName].(map[string]interface{})

	// caddy-l4 has NO server-level listener_wrappers — must not appear.
	if _, ok := srvCfg["listener_wrappers"]; ok {
		t.Errorf("server-level listener_wrappers must NOT appear (caddy-l4 rejects); got %v", srvCfg["listener_wrappers"])
	}

	// Top-level: exactly one route, two handlers (proxy_protocol then subroute).
	outer, _ := srvCfg["routes"].([]interface{})
	if len(outer) != 1 {
		t.Fatalf("expected 1 outer route (single wrapper), got %d", len(outer))
	}
	handlers, _ := outer[0].(map[string]interface{})["handle"].([]interface{})
	if len(handlers) != 2 {
		t.Fatalf("expected 2 outer handlers, got %d", len(handlers))
	}

	pp := handlers[0].(map[string]interface{})
	if pp["handler"] != "proxy_protocol" {
		t.Errorf("first handler = %v, want proxy_protocol", pp["handler"])
	}
	allow, _ := pp["allow"].([]interface{})
	if len(allow) != 1 || allow[0] != "10.130.0.13/32" {
		t.Errorf("allow = %v, want [10.130.0.13/32]", allow)
	}

	sr := handlers[1].(map[string]interface{})
	if sr["handler"] != "subroute" {
		t.Errorf("second handler = %v, want subroute", sr["handler"])
	}
	innerRoutes, _ := sr["routes"].([]interface{})
	if len(innerRoutes) != 2 {
		t.Fatalf("expected 2 inner routes (SNI + catchall), got %d", len(innerRoutes))
	}

	// Inner route 0 (SNI passthrough) — proxy handler must NOT have proxy_protocol.
	sniRoute := innerRoutes[0].(map[string]interface{})
	sniHandler := sniRoute["handle"].([]interface{})[0].(map[string]interface{})
	if sniHandler["handler"] != "proxy" {
		t.Errorf("inner[0] handler = %v, want proxy", sniHandler["handler"])
	}
	if _, hasPP := sniHandler["proxy_protocol"]; hasPP {
		t.Errorf("inner[0] (SNI route to gRPC) MUST NOT have proxy_protocol; got %v", sniHandler["proxy_protocol"])
	}

	// Inner route 1 (catchall) — proxy handler MUST have proxy_protocol: "v2".
	catchallRoute := innerRoutes[1].(map[string]interface{})
	if _, hasMatch := catchallRoute["match"]; hasMatch {
		t.Errorf("inner[1] (catchall) should not have a match clause")
	}
	catchallHandler := catchallRoute["handle"].([]interface{})[0].(map[string]interface{})
	if catchallHandler["proxy_protocol"] != "v2" {
		t.Errorf("inner[1] (catchall) proxy_protocol = %v, want v2", catchallHandler["proxy_protocol"])
	}
}

// TestL4ProxyManager_EnableL4ProxyProtocol_Idempotent: a second invocation
// against an already-wrapped server must be a no-op (no double-nesting).
func TestL4ProxyManager_EnableL4ProxyProtocol_Idempotent(t *testing.T) {
	wrapped := map[string]interface{}{
		"apps": map[string]interface{}{
			"layer4": map[string]interface{}{
				"servers": map[string]interface{}{
					L4ServerName: map[string]interface{}{
						"listen": []interface{}{":443"},
						"routes": []interface{}{
							map[string]interface{}{
								"handle": []interface{}{
									map[string]interface{}{"handler": "proxy_protocol", "allow": []interface{}{"10.130.0.13/32"}},
									map[string]interface{}{"handler": "subroute", "routes": []interface{}{}},
								},
							},
						},
					},
				},
			},
		},
	}
	srv := newFakeCaddy(wrapped)
	defer srv.Close()

	m := NewL4ProxyManager(srv.URL)
	if err := m.EnableL4ProxyProtocol([]string{"10.130.0.13/32"}); err != nil {
		t.Fatalf("idempotent call must not error: %v", err)
	}

	resp, _ := http.Get(srv.URL + "/config/")
	defer resp.Body.Close()
	var cfg map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&cfg)
	routes := cfg["apps"].(map[string]interface{})["layer4"].(map[string]interface{})["servers"].(map[string]interface{})[L4ServerName].(map[string]interface{})["routes"].([]interface{})
	if len(routes) != 1 {
		t.Errorf("expected 1 route (no double-wrapping), got %d", len(routes))
	}
}

func TestL4ProxyManager_EnableL4ProxyProtocol_RejectsEmpty(t *testing.T) {
	m := NewL4ProxyManager("http://unreachable")
	if err := m.EnableL4ProxyProtocol(nil); err == nil {
		t.Errorf("expected error on empty CIDRs")
	}
}

func TestL4ProxyManager_EnableL4ProxyProtocol_RejectsWildcard(t *testing.T) {
	m := NewL4ProxyManager("http://unreachable")
	if err := m.EnableL4ProxyProtocol([]string{"0.0.0.0/0"}); err == nil {
		t.Errorf("expected error on 0.0.0.0/0")
	}
	if err := m.EnableL4ProxyProtocol([]string{"10.0.0.0/8", "::/0"}); err == nil {
		t.Errorf("expected error on ::/0")
	}
}
