package app

import (
	"encoding/json"
	"net/http"
	"testing"
)

// srv0Of decodes the fake Caddy's full config and returns the srv0 map.
func srv0Of(t *testing.T, url string) map[string]interface{} {
	t.Helper()
	resp, err := http.Get(url + "/config/")
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	defer resp.Body.Close()
	var cfg map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&cfg)
	return cfg["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})["srv0"].(map[string]interface{})
}

func strSlice(v interface{}) []string {
	raw, _ := v.([]interface{})
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		out = append(out, x.(string))
	}
	return out
}

func eqSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func clientIPInitialConfig() map[string]interface{} {
	return map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"listen": []interface{}{":80", ":443"},
						"routes": []interface{}{
							map[string]interface{}{
								"@id":    "app.example.com",
								"match":  []interface{}{map[string]interface{}{"host": []interface{}{"app.example.com"}}},
								"handle": []interface{}{map[string]interface{}{"handler": "reverse_proxy", "upstreams": []interface{}{map[string]interface{}{"dial": "10.0.3.5:8080"}}}},
							},
						},
					},
				},
			},
		},
	}
}

// The core #1829 contract: after PROXY protocol is enabled for the sentinel,
// ConfigureClientIP must (a) set client_ip_headers, (b) widen trusted_proxies
// to the union of the sentinel set and the CDN ranges, and (c) leave the
// proxy_protocol allow list as the sentinel set only — a CDN never sends PROXY
// headers, and widening that allow list would let a CDN edge spoof a source.
func TestProxyManager_ConfigureClientIP_SetsHeadersUnionsRangesKeepsAllow(t *testing.T) {
	srv := newFakeCaddy(clientIPInitialConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "example.com")

	sentinel := []string{"10.140.0.0/16", "10.0.3.1/32"}
	cdn := []string{"173.245.48.0/20", "104.16.0.0/13"}

	if err := pm.EnableProxyProtocol(sentinel); err != nil {
		t.Fatalf("EnableProxyProtocol: %v", err)
	}
	if err := pm.ConfigureClientIP([]string{"Cf-Connecting-Ip"}, cdn); err != nil {
		t.Fatalf("ConfigureClientIP: %v", err)
	}

	srv0 := srv0Of(t, srv.URL)

	if got := strSlice(srv0["client_ip_headers"]); !eqSlice(got, []string{"Cf-Connecting-Ip"}) {
		t.Errorf("client_ip_headers = %v, want [Cf-Connecting-Ip]", got)
	}

	tp := srv0["trusted_proxies"].(map[string]interface{})
	wantRanges := []string{"10.140.0.0/16", "10.0.3.1/32", "173.245.48.0/20", "104.16.0.0/13"}
	if got := strSlice(tp["ranges"]); !eqSlice(got, wantRanges) {
		t.Errorf("trusted_proxies.ranges = %v, want union %v", got, wantRanges)
	}

	// The PROXY allow list must NOT have been widened to the CDN ranges.
	wrappers := srv0["listener_wrappers"].([]interface{})
	allow := strSlice(wrappers[0].(map[string]interface{})["allow"])
	if !eqSlice(allow, sentinel) {
		t.Errorf("proxy_protocol allow = %v, want sentinel-only %v", allow, sentinel)
	}

	// Regression: unrelated server fields survive the in-place edit.
	if l := strSlice(srv0["listen"]); !eqSlice(l, []string{":80", ":443"}) {
		t.Errorf("listen clobbered: %v", l)
	}
	if r, _ := srv0["routes"].([]interface{}); len(r) != 1 {
		t.Errorf("routes clobbered: %v", srv0["routes"])
	}
}

// Order independence: configuring client-IP trust BEFORE PROXY protocol must
// still yield the union once EnableProxyProtocol runs, and client_ip_headers
// must survive EnableProxyProtocol's rewrite of trusted_proxies.
func TestProxyManager_ConfigureClientIP_BeforeProxyProtocol_StillUnions(t *testing.T) {
	srv := newFakeCaddy(clientIPInitialConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "example.com")

	if err := pm.ConfigureClientIP([]string{"Cf-Connecting-Ip"}, []string{"104.16.0.0/13"}); err != nil {
		t.Fatalf("ConfigureClientIP: %v", err)
	}
	if err := pm.EnableProxyProtocol([]string{"10.140.0.0/16"}); err != nil {
		t.Fatalf("EnableProxyProtocol: %v", err)
	}

	srv0 := srv0Of(t, srv.URL)
	if got := strSlice(srv0["client_ip_headers"]); !eqSlice(got, []string{"Cf-Connecting-Ip"}) {
		t.Errorf("client_ip_headers lost across EnableProxyProtocol: %v", got)
	}
	tp := srv0["trusted_proxies"].(map[string]interface{})
	if got := strSlice(tp["ranges"]); !eqSlice(got, []string{"10.140.0.0/16", "104.16.0.0/13"}) {
		t.Errorf("trusted_proxies.ranges = %v, want [10.140.0.0/16 104.16.0.0/13]", got)
	}
}

// Without PROXY protocol at all (a CDN-only host), trusted_proxies is just
// the CDN ranges and no listener_wrappers are introduced.
func TestProxyManager_ConfigureClientIP_WithoutProxyProtocol(t *testing.T) {
	srv := newFakeCaddy(clientIPInitialConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "example.com")

	if err := pm.ConfigureClientIP([]string{"Cf-Connecting-Ip"}, []string{"104.16.0.0/13"}); err != nil {
		t.Fatalf("ConfigureClientIP: %v", err)
	}
	srv0 := srv0Of(t, srv.URL)
	tp := srv0["trusted_proxies"].(map[string]interface{})
	if got := strSlice(tp["ranges"]); !eqSlice(got, []string{"104.16.0.0/13"}) {
		t.Errorf("trusted_proxies.ranges = %v, want [104.16.0.0/13]", got)
	}
	if _, ok := srv0["listener_wrappers"]; ok {
		t.Error("listener_wrappers must not be introduced by ConfigureClientIP")
	}
}

func TestProxyManager_ConfigureClientIP_DedupsRanges(t *testing.T) {
	srv := newFakeCaddy(clientIPInitialConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "example.com")

	if err := pm.EnableProxyProtocol([]string{"10.0.3.1/32"}); err != nil {
		t.Fatalf("EnableProxyProtocol: %v", err)
	}
	// Operator repeats a range already in the PROXY set; it must not duplicate.
	if err := pm.ConfigureClientIP([]string{"Cf-Connecting-Ip"}, []string{"10.0.3.1/32", "104.16.0.0/13"}); err != nil {
		t.Fatalf("ConfigureClientIP: %v", err)
	}
	tp := srv0Of(t, srv.URL)["trusted_proxies"].(map[string]interface{})
	if got := strSlice(tp["ranges"]); !eqSlice(got, []string{"10.0.3.1/32", "104.16.0.0/13"}) {
		t.Errorf("trusted_proxies.ranges = %v, want deduped [10.0.3.1/32 104.16.0.0/13]", got)
	}
}

func TestProxyManager_ConfigureClientIP_RefusesWildcard(t *testing.T) {
	srv := newFakeCaddy(clientIPInitialConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "example.com")
	for _, w := range []string{"0.0.0.0/0", "::/0"} {
		if err := pm.ConfigureClientIP([]string{"Cf-Connecting-Ip"}, []string{w}); err == nil {
			t.Errorf("expected wildcard %q to be refused", w)
		}
	}
}

func TestProxyManager_ConfigureClientIP_RefusesInvalidCIDRAndEmptyHeader(t *testing.T) {
	srv := newFakeCaddy(clientIPInitialConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "example.com")
	if err := pm.ConfigureClientIP([]string{"Cf-Connecting-Ip"}, []string{"10.0.0.0\\8"}); err == nil {
		t.Error("expected malformed CIDR to be refused")
	}
	if err := pm.ConfigureClientIP([]string{"  "}, []string{"104.16.0.0/13"}); err == nil {
		t.Error("expected empty header entry to be refused")
	}
	if err := pm.ConfigureClientIP(nil, nil); err == nil {
		t.Error("expected nothing-to-configure to be refused")
	}
}

// Durability (#1829's actual complaint): after the bundled Caddy reverts to
// its stub Caddyfile, EnsureBaseConfig must re-apply the client-IP trust the
// same way it re-applies PROXY protocol — otherwise a daemon/Caddy restart
// silently drops it and every app goes back to seeing CDN edge IPs.
func TestEnsureBaseConfig_ReappliesClientIPTrust(t *testing.T) {
	srv, fc := newRWFakeCaddy(intactConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "containarium.dev")

	if err := pm.EnableProxyProtocol([]string{"127.0.0.0/8"}); err != nil {
		t.Fatalf("EnableProxyProtocol: %v", err)
	}
	if err := pm.ConfigureClientIP([]string{"Cf-Connecting-Ip"}, []string{"104.16.0.0/13"}); err != nil {
		t.Fatalf("ConfigureClientIP: %v", err)
	}

	// Simulate a Caddy reload reverting to the stub.
	fc.config = stubConfig()

	rebuilt, err := pm.EnsureBaseConfig()
	if err != nil {
		t.Fatalf("EnsureBaseConfig: %v", err)
	}
	if !rebuilt {
		t.Fatal("expected rebuilt=true after stub revert")
	}
	srv0 := getMapField(getMapField(getMapField(getMapField(fc.config, "apps"), "http"), "servers"), DefaultCaddyServerName)
	if srv0 == nil {
		t.Fatal("expected srv0 to be rebuilt")
	}
	if got := strSlice(srv0["client_ip_headers"]); !eqSlice(got, []string{"Cf-Connecting-Ip"}) {
		t.Errorf("client_ip_headers not re-applied after rebuild: %v", got)
	}
	tp, _ := srv0["trusted_proxies"].(map[string]interface{})
	if tp == nil {
		t.Fatal("trusted_proxies not re-applied after rebuild")
	}
	if got := strSlice(tp["ranges"]); !eqSlice(got, []string{"127.0.0.0/8", "104.16.0.0/13"}) {
		t.Errorf("trusted_proxies.ranges after rebuild = %v, want [127.0.0.0/8 104.16.0.0/13]", got)
	}
}

// CDN-only host (no PROXY protocol): the self-heal must still re-apply.
func TestEnsureBaseConfig_ReappliesClientIPTrust_WithoutProxyProtocol(t *testing.T) {
	srv, fc := newRWFakeCaddy(intactConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "containarium.dev")
	if err := pm.ConfigureClientIP([]string{"Cf-Connecting-Ip"}, []string{"104.16.0.0/13"}); err != nil {
		t.Fatalf("ConfigureClientIP: %v", err)
	}
	fc.config = stubConfig()
	if _, err := pm.EnsureBaseConfig(); err != nil {
		t.Fatalf("EnsureBaseConfig: %v", err)
	}
	srv0 := getMapField(getMapField(getMapField(getMapField(fc.config, "apps"), "http"), "servers"), DefaultCaddyServerName)
	if got := strSlice(srv0["client_ip_headers"]); !eqSlice(got, []string{"Cf-Connecting-Ip"}) {
		t.Errorf("client_ip_headers not re-applied (no PROXY case): %v", got)
	}
}

// A present srv0 that lost its client_ip_headers is a partial revert and must
// read as not-intact so the reconcile rebuilds it.
func TestBaseConfigIntact_MissingClientIPHeaders(t *testing.T) {
	srv, _ := newRWFakeCaddy(intactConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "containarium.dev")
	pm.clientIPHeaders = []string{"Cf-Connecting-Ip"}

	intact, err := pm.baseConfigIntact()
	if err != nil {
		t.Fatalf("baseConfigIntact: %v", err)
	}
	if intact {
		t.Error("expected intact=false when client_ip_headers missing but configured")
	}

	pm.clientIPHeaders = nil
	intact, err = pm.baseConfigIntact()
	if err != nil {
		t.Fatalf("baseConfigIntact (no client-ip): %v", err)
	}
	if !intact {
		t.Error("expected intact=true when client-IP trust is not configured")
	}
}
