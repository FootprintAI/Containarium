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

func TestL4ProxyManager_EnableL4ProxyProtocol_PatchesActive(t *testing.T) {
	// Mimic the prod shape: 2 SNI routes + 1 catch-all, all with proxy handlers.
	initial := map[string]interface{}{
		"apps": map[string]interface{}{
			"layer4": map[string]interface{}{
				"servers": map[string]interface{}{
					L4ServerName: map[string]interface{}{
						"listen": []interface{}{":443"},
						"routes": []interface{}{
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
						},
					},
				},
			},
		},
	}
	srv := newFakeCaddy(initial)
	defer srv.Close()

	m := NewL4ProxyManager(srv.URL)
	if err := m.EnableL4ProxyProtocol([]string{"10.130.0.13/32", "127.0.0.0/8"}); err != nil {
		t.Fatalf("EnableL4ProxyProtocol err = %v", err)
	}

	// Re-read the loaded config and verify shape.
	resp, err := http.Get(srv.URL + "/config/")
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	defer resp.Body.Close()
	var cfg map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&cfg)

	srvCfg := cfg["apps"].(map[string]interface{})["layer4"].(map[string]interface{})["servers"].(map[string]interface{})[L4ServerName].(map[string]interface{})

	wrappers, ok := srvCfg["listener_wrappers"].([]interface{})
	if !ok || len(wrappers) != 1 {
		t.Fatalf("listener_wrappers shape wrong: %v", srvCfg["listener_wrappers"])
	}
	w0 := wrappers[0].(map[string]interface{})
	if w0["wrapper"] != "proxy_protocol" {
		t.Errorf("wrapper = %v, want proxy_protocol", w0["wrapper"])
	}
	allow, _ := w0["allow"].([]interface{})
	if len(allow) != 2 || allow[0] != "10.130.0.13/32" {
		t.Errorf("allow CIDRs = %v, want [10.130.0.13/32 127.0.0.0/8]", allow)
	}

	// Each proxy handler should have proxy_protocol = "v2".
	routes := srvCfg["routes"].([]interface{})
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}
	for i, r := range routes {
		route := r.(map[string]interface{})
		handlers := route["handle"].([]interface{})
		for _, h := range handlers {
			handler := h.(map[string]interface{})
			if handler["handler"] != "proxy" {
				continue
			}
			if handler["proxy_protocol"] != "v2" {
				t.Errorf("route %d proxy handler proxy_protocol = %v, want v2", i, handler["proxy_protocol"])
			}
		}
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
