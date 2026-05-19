package app

import (
	"testing"
)

// fakeWakeTracker satisfies WakeTracker for tests. Returns whatever
// the configured `entries` map says about a container name.
type fakeWakeTracker struct {
	entries map[string]wakeEntryTuple
}

type wakeEntryTuple struct {
	host string
	port int
}

func (f *fakeWakeTracker) IsInWakeMode(name string) (string, int, bool) {
	if f == nil {
		return "", 0, false
	}
	e, ok := f.entries[name]
	if !ok {
		return "", 0, false
	}
	return e.host, e.port, true
}

// TestEffectiveUpstream_TrackerHit — tracker reports wake mode → the
// returned upstream is the wake host/port, not the route's
// TargetIP/TargetPort.
func TestEffectiveUpstream_TrackerHit(t *testing.T) {
	job := &RouteSyncJob{}
	job.SetWakeTracker(&fakeWakeTracker{
		entries: map[string]wakeEntryTuple{
			"alice-container": {host: "10.0.3.1", port: 8080},
		},
	})
	route := &RouteRecord{
		ContainerName: "alice-container",
		TargetIP:      "10.0.0.42",
		TargetPort:    9000,
	}
	ip, port := job.effectiveUpstream(route)
	if ip != "10.0.3.1" || port != 8080 {
		t.Errorf("effectiveUpstream = (%s,%d), want (10.0.3.1,8080)", ip, port)
	}
}

// TestEffectiveUpstream_TrackerMiss — tracker says not-in-wake-mode →
// returns the route's direct TargetIP / TargetPort.
func TestEffectiveUpstream_TrackerMiss(t *testing.T) {
	job := &RouteSyncJob{}
	job.SetWakeTracker(&fakeWakeTracker{entries: map[string]wakeEntryTuple{}})
	route := &RouteRecord{
		ContainerName: "alice-container",
		TargetIP:      "10.0.0.42",
		TargetPort:    9000,
	}
	ip, port := job.effectiveUpstream(route)
	if ip != "10.0.0.42" || port != 9000 {
		t.Errorf("effectiveUpstream = (%s,%d), want direct (10.0.0.42,9000)", ip, port)
	}
}

// TestEffectiveUpstream_NilTracker — backward compat: a job without
// SetWakeTracker behaves exactly as it did before Phase 3.
func TestEffectiveUpstream_NilTracker(t *testing.T) {
	job := &RouteSyncJob{}
	route := &RouteRecord{
		ContainerName: "alice-container",
		TargetIP:      "10.0.0.42",
		TargetPort:    9000,
	}
	ip, port := job.effectiveUpstream(route)
	if ip != "10.0.0.42" || port != 9000 {
		t.Errorf("nil tracker effectiveUpstream = (%s,%d), want (10.0.0.42,9000)", ip, port)
	}
}

// TestEffectiveUpstream_EmptyContainerName — defensive: a route record
// with no container name (legacy or hand-rolled rows) must not consult
// the tracker (it would falsely match the empty key).
func TestEffectiveUpstream_EmptyContainerName(t *testing.T) {
	job := &RouteSyncJob{}
	job.SetWakeTracker(&fakeWakeTracker{
		entries: map[string]wakeEntryTuple{
			"": {host: "10.0.3.1", port: 8080}, // shouldn't be consulted
		},
	})
	route := &RouteRecord{
		ContainerName: "",
		TargetIP:      "10.0.0.42",
		TargetPort:    9000,
	}
	ip, port := job.effectiveUpstream(route)
	if ip != "10.0.0.42" || port != 9000 {
		t.Errorf("empty-container effectiveUpstream = (%s,%d), want direct (10.0.0.42,9000)", ip, port)
	}
}

// TestNeedsUpdate_UsesEffectiveUpstream — verifies the sync loop's
// drift check consults the tracker on every tick. If a container goes
// into wake mode while a previous direct push is live in Caddy,
// needsUpdate must return true so RouteSync re-pushes the wake address.
func TestNeedsUpdate_UsesEffectiveUpstream(t *testing.T) {
	job := &RouteSyncJob{}
	job.SetWakeTracker(&fakeWakeTracker{
		entries: map[string]wakeEntryTuple{
			"alice-container": {host: "10.0.3.1", port: 8080},
		},
	})
	dbRoute := &RouteRecord{
		ContainerName: "alice-container",
		FullDomain:    "alice.example.test",
		TargetIP:      "10.0.0.42",
		TargetPort:    9000,
		Protocol:      "http",
	}
	// Caddy currently has the direct address — tracker says wake → needs update.
	caddyRoute := Route{
		FullDomain:   "alice.example.test",
		UpstreamIP:   "10.0.0.42",
		UpstreamPort: 9000,
		Protocol:     RouteProtocolHTTP,
	}
	if !job.needsUpdate(dbRoute, caddyRoute) {
		t.Errorf("needsUpdate should be true when tracker says wake but Caddy has direct")
	}

	// And the converse — Caddy already has the wake address, no update.
	caddyWake := Route{
		FullDomain:   "alice.example.test",
		UpstreamIP:   "10.0.3.1",
		UpstreamPort: 8080,
		Protocol:     RouteProtocolHTTP,
	}
	if job.needsUpdate(dbRoute, caddyWake) {
		t.Errorf("needsUpdate should be false when Caddy already matches wake address")
	}
}

// TODO: an integration-style test of RouteSyncJob.sync() against a
// real ProxyManager + real RouteStore lives more naturally under
// test/integration/; the unit tests above lock down the
// effectiveUpstream pivot point that wake mode hinges on.
