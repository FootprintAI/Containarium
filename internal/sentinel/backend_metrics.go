package sentinel

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// Backend-failover observability (#1358).
//
// On 2026-08-14 09:17 UTC the primary backend went away (host reboot, ~2.5
// min) and the sentinel failed over to a tunnel peer in under a second — the
// multi-backend design working exactly as intended. But across that entire
// real event the exported series read:
//
//	sentinel_preempted_total 0
//	sentinel_state           1
//
// Neither moved. `sentinel_preempted_total` is incremented from the GCP
// event-watcher path (handleEvent/EventPreempted), so a loss detected by the
// health checker never touches it; `sentinel_state` only leaves 1 when the
// sentinel enters maintenance, which a successful failover is precisely what
// avoids. A sentinel fronting four backends could lose them one after another
// and every series on /metrics would sit perfectly still.
//
// That also makes those two series the wrong marker for the #1349 capture
// window: the allocation blowup is tied to losing a backend, and this proves a
// backend can be lost without either series noticing.
//
// So two additions:
//
//   - sentinel_failover_total — a counter that moves on every primary switch,
//     whether or not maintenance was ever entered.
//   - sentinel_backend_healthy{backend="..."} — per-backend health, so "gcp
//     went away but we stayed up on a tunnel" is visible and alertable rather
//     than living only in the journal.
//
// sentinel_preempted_total is deliberately left alone. It answers a different
// and still-useful question — "we had nowhere to fail over to" — and conflating
// the two would lose that.

// recordFailover counts one primary-backend switch. Called from the health
// check loop; read from the /metrics HTTP goroutine, hence the atomic.
func (m *Manager) recordFailover() {
	m.failoverTotal.Add(1)
}

// FailoverCount returns the number of primary-backend failovers observed.
func (m *Manager) FailoverCount() int64 {
	return m.failoverTotal.Load()
}

// recordBackendHealth notes a backend's health transition.
//
// This deliberately keeps its own map rather than reading Backend.Healthy at
// scrape time: that field is written by the health-check loop without holding
// the pool's lock, so reading it from an HTTP goroutine is a data race. Fixing
// that properly means reworking BackendPool's concurrency contract, which is
// not something to change on the way past — a guarded copy here is cheap and
// leaves the existing semantics untouched.
func (m *Manager) recordBackendHealth(id string, healthy bool) {
	m.backendHealthMu.Lock()
	defer m.backendHealthMu.Unlock()
	if m.backendHealth == nil {
		m.backendHealth = make(map[string]bool)
	}
	m.backendHealth[id] = healthy
}

// BackendHealthSnapshot returns a copy of the per-backend health map. A copy,
// not the live map — handing out the original would put the caller's range
// loop in a race with the health-check loop's writes.
func (m *Manager) BackendHealthSnapshot() map[string]bool {
	m.backendHealthMu.RLock()
	defer m.backendHealthMu.RUnlock()
	out := make(map[string]bool, len(m.backendHealth))
	for k, v := range m.backendHealth {
		out[k] = v
	}
	return out
}

// renderBackendMetrics builds the Prometheus exposition for the failover
// counter and per-backend health. Pure, so the label rendering and ordering
// are testable without a Manager.
func renderBackendMetrics(failovers int64, health map[string]bool) string {
	var b bytes.Buffer

	fmt.Fprint(&b, "# HELP sentinel_failover_total Total primary-backend failovers, including those absorbed without entering maintenance.\n")
	fmt.Fprint(&b, "# TYPE sentinel_failover_total counter\n")
	fmt.Fprintf(&b, "sentinel_failover_total %d\n", failovers)

	// No backends registered yet (pure tunnel mode before a peer connects).
	// Emitting a TYPE line with no samples under it is noise; omit the family.
	if len(health) == 0 {
		return b.String()
	}

	ids := make([]string, 0, len(health))
	for id := range health {
		ids = append(ids, id)
	}
	// Stable order: a scrape diff should reflect real change, not Go's
	// randomised map iteration.
	sort.Strings(ids)

	// HELP/TYPE are per-family and must appear once, ahead of the samples.
	fmt.Fprint(&b, "# HELP sentinel_backend_healthy Per-backend health as seen by the sentinel: 1 healthy, 0 unhealthy.\n")
	fmt.Fprint(&b, "# TYPE sentinel_backend_healthy gauge\n")
	for _, id := range ids {
		v := 0
		if health[id] {
			v = 1
		}
		// Not %q: the value is already escaped, and %q would escape the
		// escapes.
		fmt.Fprintf(&b, "sentinel_backend_healthy{backend=\"%s\"} %d\n", escapeLabelValue(id), v)
	}
	return b.String()
}

// labelValueEscaper mirrors the Prometheus text-format rules: backslash, double
// quote and newline must be escaped inside a label value.
var labelValueEscaper = strings.NewReplacer(
	`\`, `\\`,
	`"`, `\"`,
	"\n", `\n`,
)

// escapeLabelValue makes a backend ID safe to embed in a label.
//
// Backend IDs arrive from tunnel registration rather than a fixed allowlist, so
// they are not guaranteed label-safe. One unescaped quote yields a line no
// scraper can parse — and a parse error kills the entire scrape, not just the
// offending series, so every other metric on this endpoint would vanish too.
func escapeLabelValue(s string) string {
	return labelValueEscaper.Replace(s)
}
