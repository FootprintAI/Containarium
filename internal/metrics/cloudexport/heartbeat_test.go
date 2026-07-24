package cloudexport

import (
	"errors"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// heartbeatOf returns the single heartbeat datapoint from a flattened
// collection, or fails if it is absent or duplicated. Isolating the
// lookup keeps the heartbeat tests focused on the one series they assert.
func heartbeatOf(t *testing.T, pts []point) point {
	t.Helper()
	var found []point
	for _, p := range pts {
		if p.name == MetricHeartbeat {
			found = append(found, p)
		}
	}
	if len(found) == 0 {
		t.Fatalf("heartbeat series %q not emitted", MetricHeartbeat)
	}
	if len(found) > 1 {
		t.Fatalf("heartbeat series %q emitted %d times, want exactly 1", MetricHeartbeat, len(found))
	}
	return found[0]
}

// TestHeartbeatEmittedEveryInterval covers acceptance criterion #1: a
// heartbeat/up series is emitted on every export interval while the daemon
// runs. The ManualReader stands in for the PeriodicReader; each Collect is
// one interval tick. The heartbeat must be present, integer-typed, and
// exactly 1 on every tick.
func TestHeartbeatEmittedEveryInterval(t *testing.T) {
	sources := &fakeSources{sr: sampleResources()}
	// Three consecutive ticks: the heartbeat is present with value 1 on
	// each, never drifting or dropping out.
	for tick := 1; tick <= 3; tick++ {
		rm := collectOnce(t, sources, sampleLabels())
		hb := heartbeatOf(t, flattenGauges(t, rm))
		if !hb.isInt {
			t.Fatalf("tick %d: heartbeat must be an int64 gauge, got float", tick)
		}
		if hb.ival != 1 {
			t.Fatalf("tick %d: heartbeat = %d, want 1", tick, hb.ival)
		}
	}
}

// TestHeartbeatSurvivesSourceError is the dead-man correctness guard: the
// heartbeat means "the daemon is alive and its export pipeline reaches the
// cloud," so a transient Sources error (e.g. incus briefly unavailable)
// must NOT suppress it — otherwise an incus hiccup masquerades as backend
// death and pages the operator. The host series are still skipped for that
// tick (no stale values); only the heartbeat survives.
func TestHeartbeatSurvivesSourceError(t *testing.T) {
	cases := map[string]*fakeSources{
		"sources error": {err: errors.New("incus unavailable")},
		"nil snapshot":  {sr: nil},
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			pts := flattenGauges(t, collectOnce(t, src, sampleLabels()))
			hb := heartbeatOf(t, pts)
			if hb.ival != 1 {
				t.Fatalf("heartbeat = %d, want 1 even when Sources fails", hb.ival)
			}
			// The heartbeat is the ONLY series on a failed tick: no host
			// gauge leaks a stale value.
			if len(pts) != 1 {
				t.Fatalf("expected only the heartbeat on a failed tick, got %d series", len(pts))
			}
		})
	}
}

// TestHeartbeatLabels locks the heartbeat's label allowlist from the design
// (backend_id, hostname, daemon_version) — note daemon_version, not region:
// a dead-man alert wants to see which daemon build stopped reporting. No
// tenant/org label ever appears.
func TestHeartbeatLabels(t *testing.T) {
	labels := Labels{
		BackendID:     "backend-xyz",
		Hostname:      "host-1",
		Region:        "us-central1",
		DaemonVersion: "v0.60.0",
	}
	pts := flattenGauges(t, collectOnce(t, &fakeSources{sr: sampleResources()}, labels))
	hb := heartbeatOf(t, pts)

	want := map[string]string{
		LabelBackendID:     "backend-xyz",
		LabelHostname:      "host-1",
		LabelDaemonVersion: "v0.60.0",
	}
	got := map[string]string{}
	iter := hb.attrs.Iter()
	for iter.Next() {
		kv := iter.Attribute()
		got[string(kv.Key)] = kv.Value.AsString()
	}
	// region is a host-series label, not a heartbeat label — its presence
	// here would be a leak of the wrong allowlist.
	if _, ok := got[LabelRegion]; ok {
		t.Errorf("heartbeat carries host-series label %q; heartbeat uses daemon_version, not region", LabelRegion)
	}
	if len(got) != len(want) {
		t.Fatalf("heartbeat has labels %v, want exactly %v", keysOf(got), keysOf(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("heartbeat label %q = %q, want %q", k, got[k], v)
		}
	}
}

func keysOf(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// TestHeartbeatAttributeSet is a direct unit check that the heartbeat
// label set is derived from daemon identity, isolated from the collection
// path, so a Sources implementation has no channel to inject a label.
func TestHeartbeatAttributeSet(t *testing.T) {
	l := Labels{BackendID: "b", Hostname: "h", Region: "r", DaemonVersion: "v"}
	set := l.heartbeatAttributeSet()
	if v, ok := set.Value(attribute.Key(LabelDaemonVersion)); !ok || v.AsString() != "v" {
		t.Errorf("daemon_version = %q (ok=%v), want %q", v.AsString(), ok, "v")
	}
	if _, ok := set.Value(attribute.Key(LabelRegion)); ok {
		t.Errorf("heartbeat attribute set must not carry region")
	}
}
