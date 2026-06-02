package app

import (
	"testing"
)

// TestSyncL4Routes_LatchesActiveAcrossEmptyRouteSet is the regression test for
// issue #416: the 5s route reconcile must NOT deactivate L4 (move :443 back to
// the HTTP server) when the passthrough-route set drops to zero. Deactivating
// rewrites the :443 listen address, which restarts the listener and drops
// in-flight TLS connections — surfacing as "tls: internal error" on a
// concurrent container create's response.
//
// The invariant: once L4 is active, a subsequent sync with an empty route set
// drains the SNI routes down to the catch-all but leaves L4 owning :443.
func TestSyncL4Routes_LatchesActiveAcrossEmptyRouteSet(t *testing.T) {
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
	j := &RouteSyncJob{l4ProxyManager: m}

	route := &RouteRecord{
		FullDomain: "box-a.example",
		TargetIP:   "203.0.113.7",
		TargetPort: 22,
		Protocol:   string(RouteProtocolTLSPassthrough),
		Active:     true,
	}

	// 1) First passthrough route → L4 activates, :443 moves to layer4.
	if err := j.syncL4Routes([]*RouteRecord{route}); err != nil {
		t.Fatalf("syncL4Routes(1 route): %v", err)
	}
	if !m.IsL4Active() {
		t.Fatal("L4 should be active after the first passthrough route")
	}
	assertHTTPOff443(t, srv.URL)
	if got := l4SNIs(t, m); len(got) != 1 || got[0] != "box-a.example" {
		t.Fatalf("expected 1 SNI route [box-a.example], got %v", got)
	}

	// 2) Route set empties → the OLD code deactivated L4 here (deleting the
	//    layer4 app and moving :443 back to srv0), bouncing the listener.
	//    The latch must instead keep L4 active and just drain the SNI route.
	if err := j.syncL4Routes(nil); err != nil {
		t.Fatalf("syncL4Routes(empty): %v", err)
	}
	if !m.IsL4Active() {
		t.Fatal("REGRESSION (#416): L4 was deactivated on an empty route set — " +
			"this restarts the :443 listener and drops in-flight TLS connections")
	}
	assertHTTPOff443(t, srv.URL)
	if got := l4SNIs(t, m); len(got) != 0 {
		t.Fatalf("expected SNI routes drained to none, got %v", got)
	}

	// 3) A new route arrives again → no re-activation needed (L4 still owns
	//    :443), the route is simply added. This is the steady-state CI path:
	//    box churn no longer touches the listener.
	route2 := &RouteRecord{
		FullDomain: "box-b.example",
		TargetIP:   "203.0.113.8",
		TargetPort: 22,
		Protocol:   string(RouteProtocolTLSPassthrough),
		Active:     true,
	}
	if err := j.syncL4Routes([]*RouteRecord{route2}); err != nil {
		t.Fatalf("syncL4Routes(re-add): %v", err)
	}
	if !m.IsL4Active() {
		t.Fatal("L4 should remain active across route churn")
	}
	if got := l4SNIs(t, m); len(got) != 1 || got[0] != "box-b.example" {
		t.Fatalf("expected 1 SNI route [box-b.example], got %v", got)
	}
}

// assertHTTPOff443 verifies the HTTP server is NOT listening on :443 — i.e.
// layer4 owns :443. If srv0 ever regains :443 the listener was swapped back.
func assertHTTPOff443(t *testing.T, baseURL string) {
	t.Helper()
	cfg := readConfig(t, baseURL)
	apps, _ := cfg["apps"].(map[string]interface{})
	httpApp, _ := apps["http"].(map[string]interface{})
	if httpApp == nil {
		return // no HTTP app at all is fine for this assertion
	}
	servers, _ := httpApp["servers"].(map[string]interface{})
	srv0, _ := servers["srv0"].(map[string]interface{})
	if srv0 == nil {
		return
	}
	listen, _ := srv0["listen"].([]interface{})
	for _, l := range listen {
		if l == ":443" {
			t.Fatalf("HTTP srv0 is back on :443 — layer4 no longer owns the listener (listen=%v)", listen)
		}
	}
}

func l4SNIs(t *testing.T, m *L4ProxyManager) []string {
	t.Helper()
	routes, err := m.ListL4Routes()
	if err != nil {
		t.Fatalf("ListL4Routes: %v", err)
	}
	snis := make([]string, 0, len(routes))
	for _, r := range routes {
		snis = append(snis, r.SNI)
	}
	return snis
}
