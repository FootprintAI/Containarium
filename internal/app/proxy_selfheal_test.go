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

		if r.Method == http.MethodPut {
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
