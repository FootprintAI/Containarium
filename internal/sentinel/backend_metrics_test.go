package sentinel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// #1358: on 2026-08-14 09:17 UTC the primary backend was lost (host reboot,
// ~2.5 min) and the sentinel failed over to a tunnel peer in under a second.
// Across that entire real event:
//
//	sentinel_preempted_total 0
//	sentinel_state           1
//
// Neither moved, because `preempted_total` is incremented from the GCP
// event-watcher path (handleEvent/EventPreempted) and `state` only leaves 1
// when the sentinel enters maintenance — which a successful failover avoids.
// So a multi-backend sentinel could lose backends all day and every existing
// series would sit still. These tests pin the two series that make that
// visible.

func TestRenderBackendMetrics_FailoverCounterAndPerBackendHealth(t *testing.T) {
	out := renderBackendMetrics(7, map[string]bool{
		"gcp":               false,
		"tunnel-fts-13700k": true,
		"tunnel-byoc-1":     true,
	})

	for _, want := range []string{
		"# TYPE sentinel_failover_total counter",
		"sentinel_failover_total 7",
		"# TYPE sentinel_backend_healthy gauge",
		`sentinel_backend_healthy{backend="gcp"} 0`,
		`sentinel_backend_healthy{backend="tunnel-byoc-1"} 1`,
		`sentinel_backend_healthy{backend="tunnel-fts-13700k"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n--- got ---\n%s", want, out)
		}
	}

	// HELP/TYPE are per-family, not per-sample; repeating them for each
	// labelled series is malformed exposition.
	if n := strings.Count(out, "# TYPE sentinel_backend_healthy"); n != 1 {
		t.Errorf("emitted %d TYPE lines for sentinel_backend_healthy, want exactly 1\n--- got ---\n%s", n, out)
	}
}

// Deterministic ordering keeps a scrape diff readable and keeps these tests
// from depending on Go's randomised map iteration.
func TestRenderBackendMetrics_SortsByBackendName(t *testing.T) {
	out := renderBackendMetrics(0, map[string]bool{
		"zulu": true, "alpha": true, "mike": false,
	})
	ai := strings.Index(out, `backend="alpha"`)
	mi := strings.Index(out, `backend="mike"`)
	zi := strings.Index(out, `backend="zulu"`)
	if ai < 0 || ai >= mi || mi >= zi {
		t.Errorf("backends not in sorted order (alpha=%d mike=%d zulu=%d)\n--- got ---\n%s", ai, mi, zi, out)
	}
}

// A TYPE line with no samples under it is noise for a scraper. With no
// backends registered (pure tunnel mode before any peer connects) the family
// should be absent entirely — while the counter, which is always meaningful,
// stays.
func TestRenderBackendMetrics_OmitsEmptyBackendFamily(t *testing.T) {
	out := renderBackendMetrics(2, map[string]bool{})
	if strings.Contains(out, "sentinel_backend_healthy") {
		t.Errorf("emitted an empty sentinel_backend_healthy family\n--- got ---\n%s", out)
	}
	if !strings.Contains(out, "sentinel_failover_total 2") {
		t.Errorf("dropped the failover counter along with the empty family\n--- got ---\n%s", out)
	}
}

// Backend IDs reach this from tunnel registration, so they are not guaranteed
// to be label-safe. An unescaped quote produces a line no scraper can parse,
// silently killing the whole scrape rather than just one series.
func TestRenderBackendMetrics_EscapesLabelValues(t *testing.T) {
	out := renderBackendMetrics(0, map[string]bool{`we"ird\one` + "\n": true})
	if !strings.Contains(out, `sentinel_backend_healthy{backend="we\"ird\\one\n"} 1`) {
		t.Errorf("label value not escaped\n--- got ---\n%s", out)
	}
}

func TestManagerRecordsFailoversAndBackendHealth(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{})

	if got := m.FailoverCount(); got != 0 {
		t.Fatalf("fresh manager FailoverCount = %d, want 0", got)
	}

	m.recordBackendHealth("gcp", true)
	m.recordBackendHealth("tunnel-a", true)
	// The shape of the 2026-08-14 09:17 event: primary goes unhealthy, we
	// move to a peer.
	m.recordBackendHealth("gcp", false)
	m.recordFailover()

	if got := m.FailoverCount(); got != 1 {
		t.Errorf("FailoverCount = %d, want 1", got)
	}
	snap := m.BackendHealthSnapshot()
	if snap["gcp"] != false || snap["tunnel-a"] != true {
		t.Errorf("snapshot = %v, want gcp:false tunnel-a:true", snap)
	}

	// This is the regression the issue is about: the pre-existing series must
	// still read as "nothing happened" for a health-detected loss, so the new
	// ones are genuinely carrying the signal rather than duplicating it.
	if m.PreemptCount() != 0 {
		t.Errorf("PreemptCount = %d, want 0 — a health-detected backend loss is not a GCP preemption event", m.PreemptCount())
	}
	// Deliberately no assertion on CurrentState here: a freshly constructed
	// Manager starts in maintenance until a backend proves healthy, so its
	// state says nothing about failover. The point being pinned is that the
	// pre-existing COUNTER stays still while the new one moves.
}

// The snapshot must be a copy. Handing out the live map would let an HTTP
// scrape goroutine read it while the event loop mutates it — a data race the
// -race build would fail on, intermittently and in CI rather than here.
func TestBackendHealthSnapshotIsACopy(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	m.recordBackendHealth("gcp", true)

	snap := m.BackendHealthSnapshot()
	snap["gcp"] = false
	snap["injected"] = true

	fresh := m.BackendHealthSnapshot()
	if fresh["gcp"] != true {
		t.Error("mutating the returned snapshot changed the manager's state")
	}
	if _, ok := fresh["injected"]; ok {
		t.Error("key injected into the returned snapshot reached the manager")
	}
}

// Recording happens on the health-check loop while /metrics is scraped from an
// HTTP goroutine. Run under -race (CI does) this fails if the accessors are
// not properly guarded.
func TestBackendMetricsConcurrentAccess(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				m.recordBackendHealth(fmt.Sprintf("backend-%d", i), j%2 == 0)
				m.recordFailover()
			}
		}(i)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = renderBackendMetrics(m.FailoverCount(), m.BackendHealthSnapshot())
			}
		}()
	}
	wg.Wait()

	if got := m.FailoverCount(); got != 800 {
		t.Errorf("FailoverCount = %d, want 800 — increments were lost", got)
	}
}

// The endpoint must carry the new series, not just the renderer.
func TestMetricsHandlerServesBackendSeries(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	m.recordBackendHealth("gcp", true)
	m.recordFailover()

	body := scrapeMetrics(t, m)
	for _, want := range []string{
		"sentinel_failover_total 1",
		`sentinel_backend_healthy{backend="gcp"} 1`,
		// the pre-existing families must survive
		"sentinel_preempted_total",
		"sentinel_state",
		// go_goroutines, not process_resident_memory_bytes: the process_*
		// family is correctly ABSENT where /proc is unavailable (#1351), so
		// asserting it here would fail on a macOS dev box for the right
		// reason. The runtime series are portable.
		"go_goroutines",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n--- got ---\n%s", want, body)
		}
	}
}

// scrapeMetrics drives the real /metrics handler and returns its body.
func scrapeMetrics(t *testing.T, m *Manager) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.MetricsHandler()(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// TestFailoverPrimaryCountsTheRealPath exercises failoverPrimary itself, not
// just the recorder.
//
// Without this, deleting m.recordFailover() from failoverPrimary left every
// test in this file green — the same failure mode peer_proxy_handler_test.go
// documents for #1102. switchToProxy syncs certs and keys over the network and
// rewrites iptables, so it is stubbed via the seam; everything else is the
// real control flow.
func TestFailoverPrimaryCountsTheRealPath(t *testing.T) {
	newMgr := func() (*Manager, *int) {
		m := NewManager(Config{}, &fakeRecoveryProvider{})
		calls := 0
		m.switchToProxyFn = func(*Backend) error { calls++; return nil }
		return m, &calls
	}

	t.Run("successful switch counts once", func(t *testing.T) {
		m, calls := newMgr()
		failed := &Backend{ID: "gcp", IP: "10.0.0.1", Healthy: false, Priority: 0}
		peer := &Backend{ID: "tunnel-a", IP: "10.0.0.2", Healthy: true, Priority: 10}
		m.backends.Add(failed)
		m.backends.Add(peer)

		m.failoverPrimary(context.Background(), failed)

		if *calls != 1 {
			t.Fatalf("switchToProxy called %d times, want 1", *calls)
		}
		if got := m.FailoverCount(); got != 1 {
			t.Errorf("FailoverCount = %d, want 1 — the counter is not wired into failoverPrimary", got)
		}
	})

	t.Run("failed switch is not counted", func(t *testing.T) {
		m, _ := newMgr()
		m.switchToProxyFn = func(*Backend) error { return errors.New("iptables refused") }
		failed := &Backend{ID: "gcp", IP: "10.0.0.1", Healthy: false, Priority: 0}
		peer := &Backend{ID: "tunnel-a", IP: "10.0.0.2", Healthy: true, Priority: 10}
		m.backends.Add(failed)
		m.backends.Add(peer)

		m.failoverPrimary(context.Background(), failed)

		if got := m.FailoverCount(); got != 0 {
			t.Errorf("FailoverCount = %d, want 0 — a switch that errored left the primary unchanged, "+
				"so reporting a failover would be a lie", got)
		}
	})

	t.Run("no healthy peer means maintenance, not a failover", func(t *testing.T) {
		m, calls := newMgr()
		failed := &Backend{ID: "gcp", IP: "10.0.0.1", Healthy: false, Priority: 0}
		m.backends.Add(failed)

		m.failoverPrimary(context.Background(), failed)

		if *calls != 0 {
			t.Errorf("switchToProxy called %d times with no healthy peer, want 0", *calls)
		}
		if got := m.FailoverCount(); got != 0 {
			t.Errorf("FailoverCount = %d, want 0 — this is the #1349 shape (nowhere to go), "+
				"which sentinel_state/outage_seconds already report", got)
		}
	})
}
