package sentinel

import (
	"context"
	"log"
	"time"
)

// Watch-only backend recovery.
//
// The "gcp" backend (initGCPBackend, diagnoseAndRecover in manager.go) is
// this sentinel's primary+failover HTTP proxy target: exactly one per
// process, selected by SelectPrimary. Some fleets also run a second,
// wholly independent GCP spot/preemptible VM that isn't part of that
// traffic pool at all — different tenants, different zone, no shared
// front door — but still wants the same "detect preemption, call
// StartInstance, back off exponentially on repeated failure" treatment
// (#514) instead of silently sitting stopped until a human notices.
//
// AddWatchOnlyBackend registers such a target. It is deliberately kept
// out of the Backend/BackendPool machinery used for HTTP forwarding: a
// watch-only target never becomes m.primary and is never considered by
// SelectPrimary, so it can't accidentally start receiving traffic meant
// for the real primary just because both happen to be "healthy" at the
// same instant.

// watchedBackend tracks recovery state for one watch-only target,
// independent of the Manager-level outageStart/preemptCount/
// recoveryBackoff fields used by the primary "gcp" backend — those
// assume a single outage timeline, which multiple independent targets
// would corrupt if they shared it. Each watchedBackend is touched only
// by its own runWatchOnlyRecovery goroutine, so it needs no lock (same
// single-goroutine-owns-it convention as the primary recovery fields).
type watchedBackend struct {
	id       string
	provider CloudProvider

	down                bool // true once observed stopped/terminated; cleared on running
	recoveryBackoff     time.Duration
	nextRecoveryAttempt time.Time
	lastPreemption      time.Time
	preemptCount        int
	recoveredCount      int
}

// AddWatchOnlyBackend registers an additional GCP-backed instance for
// preemption-watching and auto-restart, without adding it to the primary
// HTTP proxy pool. Call before Run(); id is used only for log lines and
// alert-webhook labeling.
func (m *Manager) AddWatchOnlyBackend(id string, provider CloudProvider) {
	m.watchOnly = append(m.watchOnly, &watchedBackend{id: id, provider: provider})
}

// runWatchOnlyRecovery is the per-target event loop: an EventWatcher (if
// the provider supports it, as GCPProvider does) for immediate reaction
// to a preemption/stop operation, plus a periodic poll as a fallback and
// as the driver for backoff-scheduled StartInstance retries. Blocks
// until ctx is cancelled.
func (m *Manager) runWatchOnlyRecovery(ctx context.Context, wb *watchedBackend) {
	log.Printf("[sentinel] watch-only(%s): recovery loop started", wb.id)

	// Check immediately at startup rather than waiting for the first
	// tick or a new event — a target that's already stopped/terminated
	// when this sentinel (re)starts should be recovered right away, not
	// after CheckInterval or the next GCP operation.
	m.diagnoseAndRecoverWatchOnly(ctx, wb)

	events := make(chan VMEvent, 10)
	if watcher, ok := wb.provider.(EventWatcher); ok {
		go func() {
			if err := watcher.WatchEvents(ctx, events); err != nil {
				log.Printf("[sentinel] watch-only(%s): event watcher error: %v", wb.id, err)
			}
		}()
	}

	pollInterval := m.config.CheckInterval
	if pollInterval <= 0 {
		pollInterval = 15 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			m.handleWatchOnlyEvent(ctx, wb, event)
		case <-ticker.C:
			m.maybeRetryWatchOnlyRecovery(ctx, wb)
		}
	}
}

func (m *Manager) handleWatchOnlyEvent(ctx context.Context, wb *watchedBackend, event VMEvent) {
	switch event.Type {
	case EventPreempted, EventStopped, EventTerminated:
		wb.lastPreemption = event.Timestamp
		wb.preemptCount++
		log.Printf("[sentinel] watch-only(%s): EVENT %s at %s — %s",
			wb.id, event.Type, event.Timestamp.Format(time.RFC3339), event.Detail)
		m.fireWatchOnlyAlert("preempted", wb, 0)
		m.diagnoseAndRecoverWatchOnly(ctx, wb)
	case EventStarted:
		log.Printf("[sentinel] watch-only(%s): EVENT started at %s — %s",
			wb.id, event.Timestamp.Format(time.RFC3339), event.Detail)
	}
}

// maybeRetryWatchOnlyRecovery re-attempts recovery on the backoff
// schedule while the target is known down. Mirrors maybeRetryRecovery's
// role for the primary backend, but gated on wb.down instead of the
// Manager's proxy state (a watch-only target never puts the sentinel
// into StateMaintenance).
func (m *Manager) maybeRetryWatchOnlyRecovery(ctx context.Context, wb *watchedBackend) {
	if !wb.down {
		return
	}
	if !wb.nextRecoveryAttempt.IsZero() && time.Now().Before(wb.nextRecoveryAttempt) {
		return
	}
	m.diagnoseAndRecoverWatchOnly(ctx, wb)
}

// diagnoseAndRecoverWatchOnly checks the target's cloud status and, if
// stopped/terminated, attempts to start it, advancing the backoff
// schedule based on the outcome. Mirrors diagnoseAndRecover's logic for
// the primary backend, against wb's own independent timeline.
func (m *Manager) diagnoseAndRecoverWatchOnly(ctx context.Context, wb *watchedBackend) {
	status, err := wb.provider.GetInstanceStatus(ctx)
	if err != nil {
		log.Printf("[sentinel] watch-only(%s): failed to get status: %v", wb.id, err)
		m.advanceWatchOnlyBackoff(wb)
		return
	}
	log.Printf("[sentinel] watch-only(%s): status %s", wb.id, status)

	switch status {
	case StatusStopped, StatusTerminated:
		wb.down = true
		log.Printf("[sentinel] watch-only(%s): attempting to start...", wb.id)
		if err := wb.provider.StartInstance(ctx); err != nil {
			log.Printf("[sentinel] watch-only(%s): failed to start: %v (will retry, backing off)", wb.id, err)
			m.advanceWatchOnlyBackoff(wb)
			return
		}
		log.Printf("[sentinel] watch-only(%s): start command sent", wb.id)
		m.scheduleWatchOnlyRecovery(wb, m.config.RecoveryBackoffInitial)
	case StatusProvisioning:
		m.scheduleWatchOnlyRecovery(wb, m.config.RecoveryBackoffInitial)
	case StatusRunning:
		if wb.down {
			wb.down = false
			wb.recoveredCount++
			wb.recoveryBackoff = 0
			wb.nextRecoveryAttempt = time.Time{}
			log.Printf("[sentinel] watch-only(%s): recovered (running)", wb.id)
			m.fireWatchOnlyAlert("recovered", wb, 0)
		}
	}
}

func (m *Manager) scheduleWatchOnlyRecovery(wb *watchedBackend, d time.Duration) {
	if d <= 0 {
		d = m.config.RecoveryBackoffInitial
	}
	wb.recoveryBackoff = d
	wb.nextRecoveryAttempt = time.Now().Add(d)
}

func (m *Manager) advanceWatchOnlyBackoff(wb *watchedBackend) {
	next := wb.recoveryBackoff * 2
	if wb.recoveryBackoff == 0 {
		next = m.config.RecoveryBackoffInitial
	}
	if next > m.config.RecoveryBackoffMax {
		next = m.config.RecoveryBackoffMax
	}
	wb.down = true
	m.scheduleWatchOnlyRecovery(wb, next)
}

// fireWatchOnlyAlert POSTs to the same AlertWebhookURL as the primary
// backend's fireAlert, but built from wb's own counters — reusing
// fireAlert directly would report the PRIMARY backend's preempt/recover
// totals under a watch-only target's event, which would be wrong.
func (m *Manager) fireWatchOnlyAlert(event string, wb *watchedBackend, outage time.Duration) {
	if m.config.AlertWebhookURL == "" {
		return
	}
	payload := alertPayload{
		Event:          event,
		Backend:        wb.id,
		PreemptedTotal: wb.preemptCount,
		RecoveredTotal: wb.recoveredCount,
		Outstanding:    wb.preemptCount - wb.recoveredCount,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}
	if outage > 0 {
		payload.OutageSeconds = int64(outage.Seconds())
	}
	postAlertPayload(m.config.AlertWebhookURL, payload)
}
