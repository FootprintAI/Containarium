package app

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestL4ProxyManager_EnableL4ProxyProtocol_NotActive: when L4 is not yet
// active, EnableL4ProxyProtocol must record the trusted CIDRs without error
// — ActivateL4 will produce the wrapped shape later when called by
// RouteSyncJob.
func TestL4ProxyManager_EnableL4ProxyProtocol_NotActive(t *testing.T) {
	srv := newFakeCaddy(map[string]interface{}{"apps": map[string]interface{}{}})
	defer srv.Close()
	m := NewL4ProxyManager(srv.URL)
	if err := m.EnableL4ProxyProtocol([]string{"10.130.0.13/32"}); err != nil {
		t.Fatalf("expected no-op when L4 inactive, got %v", err)
	}
	if !m.proxyProtocolEnabled() {
		t.Errorf("manager should remember trusted CIDRs even when L4 inactive")
	}
}

// TestL4ProxyManager_EnableL4ProxyProtocol_RejectsEmpty / _RejectsWildcard:
// same safety guards as the HTTP-side variant — refuse to wrap with an
// unrestricted allow list.
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

// TestL4ProxyManager_ActivateL4_WrappedWhenEnabled: when proxy-protocol is
// configured before ActivateL4, the activated server uses the pattern B
// shape directly.
func TestL4ProxyManager_ActivateL4_WrappedWhenEnabled(t *testing.T) {
	initial := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"listen": []interface{}{":80", ":443"},
						"routes": []interface{}{},
					},
				},
			},
		},
	}
	srv := newFakeCaddy(initial)
	defer srv.Close()

	m := NewL4ProxyManager(srv.URL)
	if err := m.SetProxyProtocolTrusted([]string{"10.130.0.13/32"}); err != nil {
		t.Fatal(err)
	}
	if err := m.ActivateL4(); err != nil {
		t.Fatalf("ActivateL4: %v", err)
	}

	cfg := readConfig(t, srv.URL)
	srvCfg := cfg["apps"].(map[string]interface{})["layer4"].(map[string]interface{})["servers"].(map[string]interface{})[L4ServerName].(map[string]interface{})
	outer := srvCfg["routes"].([]interface{})
	if len(outer) != 1 {
		t.Fatalf("expected 1 outer route (wrapped shape), got %d", len(outer))
	}
	hs := outer[0].(map[string]interface{})["handle"].([]interface{})
	if len(hs) != 2 || hs[0].(map[string]interface{})["handler"] != "proxy_protocol" {
		t.Fatalf("expected outer handlers [proxy_protocol, subroute]; got %v", hs)
	}
	innerRoutes := hs[1].(map[string]interface{})["routes"].([]interface{})
	if len(innerRoutes) != 1 {
		t.Fatalf("expected 1 inner route (catchall); got %d", len(innerRoutes))
	}
	catchallHandler := innerRoutes[0].(map[string]interface{})["handle"].([]interface{})[0].(map[string]interface{})
	if catchallHandler["proxy_protocol"] != "v2" {
		t.Errorf("catchall must emit proxy_protocol: v2; got %v", catchallHandler["proxy_protocol"])
	}
}

// TestL4ProxyManager_Lifecycle_WrappingSurvivesRouteSyncJob is the regression
// test for the prod-broke-everything bug we hit in attempt 3:
// EnableL4ProxyProtocol set up the wrap, then RouteSyncJob called
// AddL4Route / RemoveL4Route which used the old flat-routes assumption and
// clobbered the wrapping. This test simulates that exact sequence.
func TestL4ProxyManager_Lifecycle_WrappingSurvivesRouteSyncJob(t *testing.T) {
	initial := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"listen": []interface{}{":80", ":443"},
						"routes": []interface{}{},
					},
				},
			},
		},
	}
	srv := newFakeCaddy(initial)
	defer srv.Close()

	m := NewL4ProxyManager(srv.URL)
	mustEnable(t, m, []string{"10.130.0.13/32"})
	mustActivate(t, m)

	// Three RouteSyncJob-style sync cycles, each adding then removing routes.
	// In the old (broken) implementation, the first AddL4Route would unwrap
	// the server (because getRoutes/putRoutes went straight to outer routes,
	// not the inner subroute). After this test runs, the wrapping must still
	// be intact and the SNI routes must be inside the subroute.
	for i := 0; i < 3; i++ {
		if err := m.AddL4Route("grpc.kafeido.app", "10.0.3.248", 50051); err != nil {
			t.Fatalf("cycle %d AddL4Route grpc: %v", i, err)
		}
		if err := m.AddL4Route("grpc-dev.kafeido.app", "10.0.3.250", 50052); err != nil {
			t.Fatalf("cycle %d AddL4Route grpc-dev: %v", i, err)
		}
		assertWrappedAndCatchallV2(t, srv.URL, i)
	}

	// Now remove one — wrapping must still hold.
	if err := m.RemoveL4Route("grpc-dev.kafeido.app"); err != nil {
		t.Fatalf("RemoveL4Route: %v", err)
	}
	assertWrappedAndCatchallV2(t, srv.URL, 99)

	// ListL4Routes must see the 1 remaining SNI route (catchall is excluded).
	listed, err := m.ListL4Routes()
	if err != nil {
		t.Fatalf("ListL4Routes: %v", err)
	}
	if len(listed) != 1 || listed[0].SNI != "grpc.kafeido.app" {
		t.Errorf("ListL4Routes after Remove = %v, want 1 entry for grpc.kafeido.app", listed)
	}
}

// TestL4ProxyManager_EnableL4ProxyProtocol_ReshapesActiveFlatServer: when L4
// was already active in the legacy flat shape (e.g. an older daemon left it
// running), EnableL4ProxyProtocol must atomically re-shape it without
// dropping any pre-existing SNI routes.
func TestL4ProxyManager_EnableL4ProxyProtocol_ReshapesActiveFlatServer(t *testing.T) {
	flatRoutes := []interface{}{
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
		// catchall
		map[string]interface{}{
			"handle": []interface{}{
				map[string]interface{}{"handler": "proxy", "upstreams": []interface{}{
					map[string]interface{}{"dial": []interface{}{l4HTTPFallbackDial}},
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
						"routes": flatRoutes,
					},
				},
			},
		},
	}
	srv := newFakeCaddy(initial)
	defer srv.Close()

	m := NewL4ProxyManager(srv.URL)
	if err := m.EnableL4ProxyProtocol([]string{"10.130.0.13/32"}); err != nil {
		t.Fatalf("EnableL4ProxyProtocol: %v", err)
	}

	cfg := readConfig(t, srv.URL)
	srvCfg := cfg["apps"].(map[string]interface{})["layer4"].(map[string]interface{})["servers"].(map[string]interface{})[L4ServerName].(map[string]interface{})
	outer := srvCfg["routes"].([]interface{})
	if len(outer) != 1 {
		t.Fatalf("after reshape, expected 1 outer route (wrapped); got %d", len(outer))
	}
	inner := outer[0].(map[string]interface{})["handle"].([]interface{})[1].(map[string]interface{})["routes"].([]interface{})
	if len(inner) != 2 {
		t.Fatalf("after reshape, inner routes = %d, want 2 (grpc + catchall)", len(inner))
	}
	// grpc route preserved
	grpc := inner[0].(map[string]interface{})
	if matches, _ := grpc["match"].([]interface{}); len(matches) != 1 {
		t.Errorf("grpc route lost its match clause after reshape")
	}
	// catchall now has proxy_protocol: v2
	catchall := inner[1].(map[string]interface{})
	catchallH := catchall["handle"].([]interface{})[0].(map[string]interface{})
	if catchallH["proxy_protocol"] != "v2" {
		t.Errorf("catchall after reshape proxy_protocol = %v, want v2", catchallH["proxy_protocol"])
	}
}

// --- helpers ---

func mustEnable(t *testing.T, m *L4ProxyManager, cidrs []string) {
	t.Helper()
	if err := m.EnableL4ProxyProtocol(cidrs); err != nil {
		t.Fatalf("EnableL4ProxyProtocol: %v", err)
	}
}

func mustActivate(t *testing.T, m *L4ProxyManager) {
	t.Helper()
	if err := m.ActivateL4(); err != nil {
		t.Fatalf("ActivateL4: %v", err)
	}
}

func readConfig(t *testing.T, baseURL string) map[string]interface{} {
	t.Helper()
	resp, err := http.Get(baseURL + "/config/")
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	defer resp.Body.Close()
	var cfg map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return cfg
}

// assertWrappedAndCatchallV2 verifies the L4 server is in pattern B shape and
// the catchall (last inner route, no match clause) emits proxy_protocol: v2.
func assertWrappedAndCatchallV2(t *testing.T, baseURL string, cycle int) {
	t.Helper()
	cfg := readConfig(t, baseURL)
	srvCfg := cfg["apps"].(map[string]interface{})["layer4"].(map[string]interface{})["servers"].(map[string]interface{})[L4ServerName].(map[string]interface{})
	outer, _ := srvCfg["routes"].([]interface{})
	if len(outer) != 1 {
		t.Fatalf("[cycle %d] expected 1 outer route (wrapping intact); got %d (%v)", cycle, len(outer), srvCfg["routes"])
	}
	hs := outer[0].(map[string]interface{})["handle"].([]interface{})
	if hs[0].(map[string]interface{})["handler"] != "proxy_protocol" {
		t.Fatalf("[cycle %d] outer handler 0 = %v, want proxy_protocol", cycle, hs[0])
	}
	inner := hs[1].(map[string]interface{})["routes"].([]interface{})
	if len(inner) == 0 {
		t.Fatalf("[cycle %d] inner subroute has no routes — wrapping was clobbered", cycle)
	}
	last := inner[len(inner)-1].(map[string]interface{})
	if _, hasMatch := last["match"]; hasMatch {
		t.Fatalf("[cycle %d] last inner route has a match clause — catchall is missing/displaced", cycle)
	}
	lastH := last["handle"].([]interface{})[0].(map[string]interface{})
	if lastH["proxy_protocol"] != "v2" {
		t.Errorf("[cycle %d] catchall proxy_protocol = %v, want v2", cycle, lastH["proxy_protocol"])
	}
}
