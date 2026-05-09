package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeCaddy is a minimal stand-in for the Caddy admin API. It serves a stored
// config snapshot at GET endpoints and accepts POST /load to replace it.
type fakeCaddy struct {
	config map[string]interface{}
	loads  int
}

func newFakeCaddy(initial map[string]interface{}) *httptest.Server {
	fc := &fakeCaddy{config: initial}
	mux := http.NewServeMux()
	mux.HandleFunc("/config/", func(w http.ResponseWriter, r *http.Request) {
		// Path semantics:
		//   GET /config/                                  -> full config
		//   GET /config/apps/layer4/servers/<name>        -> the L4 server
		//   POST /load                                    -> handled separately
		path := strings.TrimPrefix(r.URL.Path, "/config/")
		path = strings.TrimSuffix(path, "/")
		if path == "" {
			_ = json.NewEncoder(w).Encode(fc.config)
			return
		}
		// Walk the path through the config tree.
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
	srv := httptest.NewServer(mux)
	srv.Config.Handler = mux
	return srv
}

func TestL4ProxyManager_EnableL4ProxyProtocol_NotActive(t *testing.T) {
	// L4 not in config — must be a no-op (no error, no /load).
	srv := newFakeCaddy(map[string]interface{}{
		"apps": map[string]interface{}{},
	})
	defer srv.Close()

	m := NewL4ProxyManager(srv.URL)
	if err := m.EnableL4ProxyProtocol([]string{"10.0.0.1/32"}); err != nil {
		t.Fatalf("expected no error when L4 inactive, got %v", err)
	}
}

func TestL4ProxyManager_EnableL4ProxyProtocol_WrapsRoutes(t *testing.T) {
	// Mimic prod: 2 SNI routes + 1 catch-all.
	originalRoutes := []interface{}{
		map[string]interface{}{
			"match": []interface{}{
				map[string]interface{}{"tls": map[string]interface{}{"sni": []interface{}{"a.example"}}},
			},
			"handle": []interface{}{
				map[string]interface{}{"handler": "proxy", "upstreams": []interface{}{
					map[string]interface{}{"dial": []interface{}{"10.0.3.1:5000"}},
				}},
			},
		},
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

	// Re-read the loaded config and verify the wrapped shape.
	resp, err := http.Get(srv.URL + "/config/")
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	defer resp.Body.Close()
	var cfg map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&cfg)

	srvCfg := cfg["apps"].(map[string]interface{})["layer4"].(map[string]interface{})["servers"].(map[string]interface{})[L4ServerName].(map[string]interface{})

	// caddy-l4 has NO server-level listener_wrappers field — must not be present.
	if _, ok := srvCfg["listener_wrappers"]; ok {
		t.Errorf("listener_wrappers must NOT appear at L4 server level (caddy-l4 rejects it); got %v", srvCfg["listener_wrappers"])
	}

	outer, ok := srvCfg["routes"].([]interface{})
	if !ok || len(outer) != 2 {
		t.Fatalf("expected 2 outer routes (proxy_protocol-matched + fallback), got %v", srvCfg["routes"])
	}

	// Outer route 0: proxy_protocol matcher + subroute with v2-tagged handlers.
	if !isProxyProtocolMatchRoute(outer[0].(map[string]interface{})) {
		t.Errorf("outer route 0 should have proxy_protocol matcher; got %v", outer[0])
	}
	subroute0 := outer[0].(map[string]interface{})["handle"].([]interface{})[0].(map[string]interface{})
	if subroute0["handler"] != "subroute" {
		t.Fatalf("outer 0 handler should be subroute, got %v", subroute0["handler"])
	}
	innerRoutes0 := subroute0["routes"].([]interface{})
	if len(innerRoutes0) != 2 {
		t.Fatalf("inner subroute 0 should have 2 routes, got %d", len(innerRoutes0))
	}
	for i, ir := range innerRoutes0 {
		handlers := ir.(map[string]interface{})["handle"].([]interface{})
		for _, h := range handlers {
			handler := h.(map[string]interface{})
			if handler["handler"] == "proxy" && handler["proxy_protocol"] != "v2" {
				t.Errorf("inner-0 route %d proxy handler proxy_protocol=%v, want v2", i, handler["proxy_protocol"])
			}
		}
	}

	// Outer route 1: fallback (no match clause, original routes unmodified).
	if _, hasMatch := outer[1].(map[string]interface{})["match"]; hasMatch {
		t.Errorf("outer route 1 (fallback) should have no match clause")
	}
	subroute1 := outer[1].(map[string]interface{})["handle"].([]interface{})[0].(map[string]interface{})
	innerRoutes1 := subroute1["routes"].([]interface{})
	for i, ir := range innerRoutes1 {
		handlers := ir.(map[string]interface{})["handle"].([]interface{})
		for _, h := range handlers {
			handler := h.(map[string]interface{})
			if handler["handler"] == "proxy" {
				if _, hasPP := handler["proxy_protocol"]; hasPP {
					t.Errorf("fallback inner route %d MUST NOT have proxy_protocol set; got %v", i, handler["proxy_protocol"])
				}
			}
		}
	}
}

// Idempotency: calling EnableL4ProxyProtocol on already-wrapped routes must
// be a no-op (no double-wrapping).
func TestL4ProxyManager_EnableL4ProxyProtocol_Idempotent(t *testing.T) {
	wrapped := map[string]interface{}{
		"apps": map[string]interface{}{
			"layer4": map[string]interface{}{
				"servers": map[string]interface{}{
					L4ServerName: map[string]interface{}{
						"listen": []interface{}{":443"},
						"routes": []interface{}{
							map[string]interface{}{
								"match": []interface{}{
									map[string]interface{}{"proxy_protocol": map[string]interface{}{}},
								},
								"handle": []interface{}{
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
		t.Errorf("expected route count to stay at 1 (no double-wrapping), got %d", len(routes))
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
