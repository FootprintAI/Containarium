package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rwFakeCaddy is a fuller stand-in for the Caddy admin API than newFakeCaddy:
// it also honours PUT on a /config/<path> (creating intermediate maps), which
// is what EnsureServerConfig / createHTTPApp / createTLSApp use to rebuild the
// base config. GET walks the tree; POST /load replaces it; PUT sets a subtree.
type rwFakeCaddy struct {
	config map[string]interface{}
	loads  int
	puts   int
}

func newRWFakeCaddy(initial map[string]interface{}) (*httptest.Server, *rwFakeCaddy) {
	if initial == nil {
		initial = map[string]interface{}{}
	}
	fc := &rwFakeCaddy{config: initial}
	mux := http.NewServeMux()
	mux.HandleFunc("/config/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/config/")
		path = strings.TrimSuffix(path, "/")

		// PATCH is treated like PUT: ProvisionTLS writes the policy array back
		// with PATCH, and for a whole-node replacement the two are equivalent.
		if r.Method == http.MethodPut || r.Method == http.MethodPatch {
			body, _ := io.ReadAll(r.Body)
			var val interface{}
			if err := json.Unmarshal(body, &val); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			segs := strings.Split(path, "/")
			node := fc.config
			for _, p := range segs[:len(segs)-1] {
				next, ok := node[p].(map[string]interface{})
				if !ok {
					next = map[string]interface{}{}
					node[p] = next
				}
				node = next
			}
			node[segs[len(segs)-1]] = val
			fc.puts++
			w.WriteHeader(http.StatusOK)
			return
		}

		// GET
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
	// DELETE /id/<route-id> — real Caddy's @id addressing, used by
	// ProxyManager.RemoveRoute. Removes the matching route from the http
	// server's route list. Additive: no pre-existing test uses this path.
	mux.HandleFunc("/id/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/id/")
		apps, _ := fc.config["apps"].(map[string]interface{})
		httpApp, _ := apps["http"].(map[string]interface{})
		servers, _ := httpApp["servers"].(map[string]interface{})
		srv, _ := servers[DefaultCaddyServerName].(map[string]interface{})
		routes, _ := srv["routes"].([]interface{})

		kept := make([]interface{}, 0, len(routes))
		found := false
		for _, rt := range routes {
			m, _ := rt.(map[string]interface{})
			if m != nil {
				if got, _ := m["@id"].(string); got == id {
					found = true
					continue
				}
			}
			kept = append(kept, rt)
		}
		if !found {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		srv["routes"] = kept
		fc.puts++
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/load", func(w http.ResponseWriter, r *http.Request) {
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
	return httptest.NewServer(mux), fc
}

// intactConfig is a config tree with the http app + srv0 already present.
func intactConfig() map[string]interface{} {
	return map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					DefaultCaddyServerName: map[string]interface{}{
						"listen": []interface{}{":80", ":443"},
						"routes": []interface{}{},
					},
				},
			},
			"tls": map[string]interface{}{"automation": map[string]interface{}{}},
		},
	}
}

// stubConfig mirrors the bundled Caddy's stub Caddyfile state: admin only, no
// apps at all.
func stubConfig() map[string]interface{} {
	return map[string]interface{}{
		"admin": map[string]interface{}{"listen": ":2019"},
	}
}

func TestEnsureBaseConfig_IntactIsNoOp(t *testing.T) {
	srv, fc := newRWFakeCaddy(intactConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "containarium.dev")

	rebuilt, err := pm.EnsureBaseConfig()
	if err != nil {
		t.Fatalf("EnsureBaseConfig: %v", err)
	}
	if rebuilt {
		t.Error("expected rebuilt=false when config is intact")
	}
	if fc.loads != 0 || fc.puts != 0 {
		t.Errorf("expected no writes when intact, got loads=%d puts=%d", fc.loads, fc.puts)
	}
}

func TestEnsureBaseConfig_RebuildsFromStub(t *testing.T) {
	srv, fc := newRWFakeCaddy(stubConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "containarium.dev")

	rebuilt, err := pm.EnsureBaseConfig()
	if err != nil {
		t.Fatalf("EnsureBaseConfig: %v", err)
	}
	if !rebuilt {
		t.Fatal("expected rebuilt=true when config reverted to stub")
	}
	if fc.puts == 0 {
		t.Error("expected the rebuild to PUT the http app, but no PUTs happened")
	}

	// The srv0 server must now exist again.
	srvNode := getMapField(getMapField(getMapField(getMapField(fc.config, "apps"), "http"), "servers"), DefaultCaddyServerName)
	if srvNode == nil {
		t.Fatal("expected apps.http.servers.srv0 to be present after rebuild")
	}

	// A second call is now a no-op (idempotent).
	rebuilt, err = pm.EnsureBaseConfig()
	if err != nil {
		t.Fatalf("EnsureBaseConfig (2nd): %v", err)
	}
	if rebuilt {
		t.Error("expected rebuilt=false on the second call (already healed)")
	}
}

func TestEnsureBaseConfig_ReappliesProxyProtocol(t *testing.T) {
	srv, fc := newRWFakeCaddy(intactConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "containarium.dev")

	// Enable PROXY protocol against the intact config — this records the
	// trusted set on the manager and installs listener_wrappers on srv0.
	if err := pm.EnableProxyProtocol([]string{"127.0.0.0/8"}); err != nil {
		t.Fatalf("EnableProxyProtocol: %v", err)
	}
	srv0 := getMapField(getMapField(getMapField(getMapField(fc.config, "apps"), "http"), "servers"), DefaultCaddyServerName)
	if _, ok := srv0["listener_wrappers"]; !ok {
		t.Fatal("precondition: listener_wrappers should be set after EnableProxyProtocol")
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

	// srv0 must be back AND carry the PROXY listener wrappers again.
	srv0 = getMapField(getMapField(getMapField(getMapField(fc.config, "apps"), "http"), "servers"), DefaultCaddyServerName)
	if srv0 == nil {
		t.Fatal("expected srv0 to be rebuilt")
	}
	if _, ok := srv0["listener_wrappers"]; !ok {
		t.Error("expected listener_wrappers to be re-applied after rebuild")
	}
}

func TestBaseConfigIntact_MissingWrappersWhenProxyEnabled(t *testing.T) {
	// srv0 exists but has no listener_wrappers; with PROXY protocol expected,
	// that's a partial revert and must be treated as not-intact.
	srv, _ := newRWFakeCaddy(intactConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "containarium.dev")
	pm.proxyProtocolTrusted = []string{"127.0.0.0/8"}

	intact, err := pm.baseConfigIntact()
	if err != nil {
		t.Fatalf("baseConfigIntact: %v", err)
	}
	if intact {
		t.Error("expected intact=false when listener_wrappers missing and PROXY enabled")
	}

	// Without PROXY protocol configured, the bare server is fine.
	pm.proxyProtocolTrusted = nil
	intact, err = pm.baseConfigIntact()
	if err != nil {
		t.Fatalf("baseConfigIntact (no proxy): %v", err)
	}
	if !intact {
		t.Error("expected intact=true for a present server when PROXY not configured")
	}
}

// --- BYOC public-HTTP-ingress plaintext listener (#733 slice 3) ---

// listenSetFromRebuild rebuilds the base config from a stub and returns srv0's
// listen set as a string slice.
func listenSetFromRebuild(t *testing.T, pm *ProxyManager, fc *rwFakeCaddy) []string {
	t.Helper()
	if _, err := pm.EnsureBaseConfig(); err != nil {
		t.Fatalf("EnsureBaseConfig: %v", err)
	}
	srvNode := getMapField(getMapField(getMapField(getMapField(fc.config, "apps"), "http"), "servers"), DefaultCaddyServerName)
	if srvNode == nil {
		t.Fatal("expected srv0 present after rebuild")
	}
	raw, ok := srvNode["listen"].([]interface{})
	if !ok {
		t.Fatalf("srv0.listen is not a list: %T", srvNode["listen"])
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, v.(string))
	}
	return out
}

func TestListenAddrs_DefaultUnchanged(t *testing.T) {
	pm := NewProxyManager("http://unused", "containarium.dev")
	got := pm.listenAddrs()
	want := []string{":80", ":443"}
	if len(got) != len(want) {
		t.Fatalf("default listen set = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("default listen set = %v, want %v", got, want)
		}
	}
	if pm.BYOCIngressAddr() != "" {
		t.Errorf("BYOCIngressAddr should be empty by default, got %q", pm.BYOCIngressAddr())
	}
}

func TestListenAddrs_WithBYOCIngress(t *testing.T) {
	pm := NewProxyManager("http://unused", "containarium.dev").WithBYOCIngress("127.0.0.1:8081")
	got := pm.listenAddrs()
	want := []string{":80", ":443", "127.0.0.1:8081"}
	if len(got) != len(want) {
		t.Fatalf("listen set = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("listen set = %v, want %v", got, want)
		}
	}
	if pm.BYOCIngressAddr() != "127.0.0.1:8081" {
		t.Errorf("BYOCIngressAddr = %q, want 127.0.0.1:8081", pm.BYOCIngressAddr())
	}
}

func TestWithBYOCIngress_TrimsAndEmptyIsNoop(t *testing.T) {
	pm := NewProxyManager("http://unused", "containarium.dev").WithBYOCIngress("  127.0.0.1:9000  ")
	if pm.BYOCIngressAddr() != "127.0.0.1:9000" {
		t.Errorf("addr should be trimmed, got %q", pm.BYOCIngressAddr())
	}
	pm.WithBYOCIngress("   ")
	if pm.BYOCIngressAddr() != "" {
		t.Errorf("blank addr should disable, got %q", pm.BYOCIngressAddr())
	}
}

// The ingress listener must survive the #400 self-heal rebuild — a Caddy revert
// then EnsureBaseConfig must re-emit srv0 with the plaintext listener, else a
// Caddy reload would silently drop the BYOC data path.
func TestBYOCIngress_SurvivesSelfHealRebuild(t *testing.T) {
	srv, fc := newRWFakeCaddy(stubConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "containarium.dev").WithBYOCIngress("127.0.0.1:8081")

	got := listenSetFromRebuild(t, pm, fc)
	found := false
	for _, a := range got {
		if a == "127.0.0.1:8081" {
			found = true
		}
	}
	if !found {
		t.Errorf("rebuilt srv0.listen = %v, want it to include the BYOC ingress listener 127.0.0.1:8081", got)
	}
}

// A manager WITHOUT the ingress configured must rebuild to exactly :80,:443 —
// region hosts are byte-identical to before #733.
func TestBYOCIngress_DisabledRebuildIsUnchanged(t *testing.T) {
	srv, fc := newRWFakeCaddy(stubConfig())
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "containarium.dev")

	got := listenSetFromRebuild(t, pm, fc)
	if len(got) != 2 || got[0] != ":80" || got[1] != ":443" {
		t.Errorf("rebuilt srv0.listen = %v, want exactly [:80 :443] when BYOC ingress is off", got)
	}
}

// --- HTTP server must not reclaim :443 while L4 owns it (#1743) ---
//
// L4ProxyManager.ActivateL4 moves the HTTP server off :443 onto :8443 (see
// l4_proxy.go's moveHTTPServerOff443) so its layer4 app can own :443
// exclusively — it has to see every connection to inspect SNI before
// routing. Before this fix, listenAddrs() named :443 unconditionally, so
// the very next EnsureServerConfig (a plain daemon restart is enough) saw
// it "missing" from the HTTP server and added it back. With both servers
// bound to :443, the kernel load-balances new connections between them:
// roughly half of them land on the HTTP server, which has no route or
// certificate for an SNI-passthrough-only hostname, and the client sees a
// bare TLS handshake failure — intermittent and silent at the application
// level.

// activeL4Config returns a Caddy config with an active layer4 app (as
// ActivateL4 would leave it) and an HTTP server whose listen set is
// caller-supplied, so a test can set up the "already correctly off :443"
// starting point without going through the full activation flow.
func activeL4Config(httpListen []string) map[string]interface{} {
	return map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					DefaultCaddyServerName: map[string]interface{}{
						"listen": toAnySlice(httpListen),
						"routes": []interface{}{},
					},
				},
			},
			"layer4": map[string]interface{}{
				"servers": map[string]interface{}{
					L4ServerName: map[string]interface{}{
						"listen": []interface{}{":443"},
					},
				},
			},
			"tls": map[string]interface{}{"automation": map[string]interface{}{"policies": []interface{}{}}},
		},
	}
}

// listenSetFromConfig reads back a named server's listen array directly from
// the fake's current config tree, with no rebuild — unlike
// listenSetFromRebuild, the point here is to observe whether
// EnsureServerConfig changed anything at all.
func listenSetFromConfig(t *testing.T, fc *rwFakeCaddy, serverName string) []string {
	t.Helper()
	srvNode := getMapField(getMapField(getMapField(getMapField(fc.config, "apps"), "http"), "servers"), serverName)
	if srvNode == nil {
		t.Fatalf("expected server %q present in config", serverName)
	}
	raw, ok := srvNode["listen"].([]interface{})
	if !ok {
		t.Fatalf("%s.listen is not a list: %T", serverName, srvNode["listen"])
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, v.(string))
	}
	return out
}

func TestListenAddrs_ExcludesL443WhenL4Active(t *testing.T) {
	srv, _ := newRWFakeCaddy(activeL4Config([]string{":80", ":8443"}))
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "containarium.dev")

	got := pm.listenAddrs()
	if len(got) != 1 || got[0] != ":80" {
		t.Fatalf("listenAddrs() = %v, want [:80] — L4 owns :443, the HTTP server must not claim it too", got)
	}
}

func TestEnsureServerConfig_DoesNotReclaim443WhenL4Active(t *testing.T) {
	srv, fc := newRWFakeCaddy(activeL4Config([]string{":80", ":8443"}))
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "containarium.dev")

	if err := pm.EnsureServerConfig(); err != nil {
		t.Fatalf("EnsureServerConfig: %v", err)
	}

	got := listenSetFromConfig(t, fc, DefaultCaddyServerName)
	if len(got) != 2 || got[0] != ":80" || got[1] != ":8443" {
		t.Fatalf("srv0.listen after EnsureServerConfig = %v, want unchanged [:80 :8443] — :443 must not be reclaimed while L4 owns it", got)
	}
	if fc.puts != 0 || fc.loads != 0 {
		t.Errorf("EnsureServerConfig wrote to Caddy (%d puts, %d loads) though nothing needed to change", fc.puts, fc.loads)
	}
}

// Contrast case: the same "srv0 missing :443" starting shape as above, but
// no layer4 app at all — this really is an ordinary drift that
// EnsureServerConfig should still repair, proving the fix didn't
// overcorrect into never restoring :443 at all.
func TestEnsureServerConfig_StillReclaims443WhenL4NotActive(t *testing.T) {
	cfg := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					DefaultCaddyServerName: map[string]interface{}{
						"listen": []interface{}{":80"},
						"routes": []interface{}{},
					},
				},
			},
			"tls": map[string]interface{}{"automation": map[string]interface{}{"policies": []interface{}{}}},
		},
	}
	srv, fc := newRWFakeCaddy(cfg)
	defer srv.Close()
	pm := NewProxyManager(srv.URL, "containarium.dev")

	if err := pm.EnsureServerConfig(); err != nil {
		t.Fatalf("EnsureServerConfig: %v", err)
	}

	got := listenSetFromConfig(t, fc, DefaultCaddyServerName)
	found443 := false
	for _, a := range got {
		if a == ":443" {
			found443 = true
		}
	}
	if !found443 {
		t.Errorf("srv0.listen after EnsureServerConfig = %v, want :443 restored — L4 isn't active, so nothing else owns it", got)
	}
}
