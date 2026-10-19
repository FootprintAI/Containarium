package server

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// sentryHealthInterval is how often SentryHealth re-checks the sentry. The
// first check runs immediately at startup, so a fault is recorded well inside
// the 60 s the #2634 acceptance criterion allows.
const sentryHealthInterval = 60 * time.Second

// sentryHealthStore is what SentryHealth needs from a finding store: the
// engine's deduping upsert plus Resolve (to close a finding on recovery) and
// List (to adopt a row an earlier process left open). *FindingStore and
// *MemFindingStore both satisfy it.
type sentryHealthStore interface {
	threatdetect.FindingSink
	threatdetect.FindingReader
}

// SentryHealth raises a MEDIUM SENTRY_UNAVAILABLE finding while an armed
// backend's sentry is not running cleanly — UNAVAILABLE, DEGRADED, or any
// rule unhealthy — and resolves it once the sentry reports OK (#2634; design
// component 6 in docs/architecture/process-exec-guardrail.md).
//
// Deliberately not a threatdetect.Rule: a rule only runs inside a working
// engine, and the faults this reports are exactly the ones where the engine
// is missing or broken. The finding goes through the ordinary store, so the
// store's notifier delivers it to the webhook like any other finding.
type SentryHealth struct {
	status    func() *pb.GetSentryStatusResponse
	store     sentryHealthStore
	backendID func() string
	newTicker func(time.Duration) (<-chan time.Time, func())
	interval  time.Duration

	mu      sync.Mutex
	adopted bool             // rows left open by an earlier process were loaded
	open    map[int64]string // open SENTRY_UNAVAILABLE finding id -> subject
}

// NewSentryHealth builds the loop. status is the unauthenticated sentry
// status (ThreatDetectionServer.sentryStatus); backendID is read at write
// time because the local backend id is only known once the peer pool
// starts. newTicker nil means a real time.Ticker.
func NewSentryHealth(status func() *pb.GetSentryStatusResponse, store sentryHealthStore, backendID func() string, newTicker func(time.Duration) (<-chan time.Time, func()), interval time.Duration) *SentryHealth {
	if newTicker == nil {
		newTicker = func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		}
	}
	if backendID == nil {
		backendID = func() string { return "" }
	}
	return &SentryHealth{
		status:    status,
		store:     store,
		backendID: backendID,
		newTicker: newTicker,
		interval:  interval,
		open:      make(map[int64]string),
	}
}

// newSentryHealthIfArmed returns nil — no loop, nothing ever raised — when
// CONTAINARIUM_THREAT_SENTRY is unset (unarmed is a choice, not a fault), or
// when there is no finding store to write into (it needs the audit store,
// which needs Postgres; dual_server logs that case).
func newSentryHealthIfArmed(armed bool, status func() *pb.GetSentryStatusResponse, store sentryHealthStore, backendID func() string) *SentryHealth {
	if !armed || store == nil {
		return nil
	}
	return NewSentryHealth(status, store, backendID, nil, sentryHealthInterval)
}

// Run checks once immediately, then every interval, until ctx is done.
func (h *SentryHealth) Run(ctx context.Context) {
	h.Check(ctx)
	ticks, stop := h.newTicker(h.interval)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			h.Check(ctx)
		}
	}
}

// Check runs one health pass: upsert the finding for the current reason
// while unhealthy, and resolve every open finding whose subject is no longer
// the current reason (all of them once healthy).
func (h *SentryHealth) Check(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()

	subject, note, unhealthy := sentryUnhealthySubject(h.status())
	backendID := h.backendID()
	h.adoptLocked(ctx, backendID)

	for id, open := range h.open {
		if unhealthy && open == subject {
			continue
		}
		if _, err := h.store.Resolve(ctx, id); err != nil && !errors.Is(err, threatdetect.ErrFindingNotOpen) && !errors.Is(err, threatdetect.ErrFindingNotFound) {
			log.Printf("[sentry-health] resolve finding %d (%q): %v", id, open, err)
			continue // retried next tick
		}
		delete(h.open, id)
	}

	if !unhealthy {
		return
	}
	f, err := h.store.Upsert(ctx, &threatdetect.Finding{
		Rule:      pb.ThreatRuleId_THREAT_RULE_ID_SENTRY_UNAVAILABLE,
		Severity:  pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM,
		BackendID: backendID,
		Subject:   subject,
		Evidence:  threatdetect.Evidence{Configs: []threatdetect.ConfigEvidence{{Note: note}}},
	})
	if err != nil {
		log.Printf("[sentry-health] upsert SENTRY_UNAVAILABLE (%q): %v", note, err)
		return
	}
	h.open[f.ID] = f.Subject
}

// adoptLocked loads, once, the open SENTRY_UNAVAILABLE rows for this backend
// that an earlier daemon process left behind, so a restart onto a healthy
// sentry resolves them instead of leaving them open forever. The query is
// narrowed to this rule and backend in the store, so open findings of other
// rules cannot push a stale row out of the page; the 200-row cap then bounds
// only distinct open reasons on one backend, which in practice is a handful.
// A List failure is retried on the next tick.
func (h *SentryHealth) adoptLocked(ctx context.Context, backendID string) {
	if h.adopted {
		return
	}
	rows, err := h.store.List(ctx, threatdetect.ListFilter{
		State:     threatdetect.FindingStateOpen,
		Rule:      pb.ThreatRuleId_THREAT_RULE_ID_SENTRY_UNAVAILABLE,
		BackendID: backendID,
		Limit:     200,
	})
	if err != nil {
		log.Printf("[sentry-health] list open findings: %v", err)
		return
	}
	for _, f := range rows {
		h.open[f.ID] = f.Subject
	}
	h.adopted = true
}

// sentryUnhealthySubject reports whether resp describes an armed sentry that
// is not running cleanly. note is the full status reason, exactly as
// `containarium security sentry status` prints it, and goes into the
// finding's evidence. subject is the same reason with each unhealthy rule's
// error text dropped ("rule DENY_BURST unhealthy: panic: …" becomes "rule
// DENY_BURST unhealthy"): a panic message can vary between checks (an index,
// an address), and a varying subject would resolve one finding and open
// another on every tick instead of deduping into one row. DISABLED is not a
// fault (the loop never runs unarmed anyway).
func sentryUnhealthySubject(resp *pb.GetSentryStatusResponse) (subject, note string, unhealthy bool) {
	cpuDown := cpuSamplerUnavailable(resp)
	switch resp.GetState() {
	case pb.SentryState_SENTRY_STATE_DISABLED:
		return "", "", false
	case pb.SentryState_SENTRY_STATE_OK:
		if !anyRuleUnhealthy(resp) {
			if !cpuDown {
				return "", "", false
			}
			// Only the CPU sampler is down: the status reason is empty, so the
			// finding is about the sampler alone (#2660).
			return cpuSamplerSubject, "cpu-sampler: " + resp.GetCpuSampler(), true
		}
		note = reasonOr(resp, "a rule is unhealthy")
	default: // UNAVAILABLE, DEGRADED, UNSPECIFIED
		note = reasonOr(resp, "sentry state "+strings.TrimPrefix(resp.GetState().String(), "SENTRY_STATE_"))
	}
	subject = note
	for _, r := range resp.GetRules() {
		if r.GetHealthy() || r.GetLastError() == "" {
			continue
		}
		prefix := ruleUnhealthyPrefix(r.GetRule())
		subject = strings.ReplaceAll(subject, prefix+": "+r.GetLastError(), prefix)
	}
	if cpuDown {
		// Both faults are one finding: its subject names the sampler without
		// its varying detail, its note carries the detail.
		subject += "; " + cpuSamplerSubject
		note += "; cpu-sampler: " + resp.GetCpuSampler()
	}
	return subject, note, true
}

// cpuSamplerSubject is the stable subject of a CPU-sampler fault; the
// sampler's own reason ("unavailable (incus client unavailable: …)") varies
// and lives in the finding's evidence note.
const cpuSamplerSubject = "cpu-sampler unavailable"

// cpuSamplerUnavailable reports whether the status says the CPU sampler
// cannot run (GetSentryStatusResponse.cpu_sampler begins "unavailable"; #2645).
// An armed backend blind to CPU is not silent (#2660).
func cpuSamplerUnavailable(resp *pb.GetSentryStatusResponse) bool {
	return strings.HasPrefix(resp.GetCpuSampler(), "unavailable")
}

func anyRuleUnhealthy(resp *pb.GetSentryStatusResponse) bool {
	for _, r := range resp.GetRules() {
		if !r.GetHealthy() {
			return true
		}
	}
	return false
}

// ruleUnhealthyPrefix is the stable head of an unhealthy rule's part of the
// status reason; ThreatDetectionServer.sentryStatus appends ": <last_error>".
func ruleUnhealthyPrefix(rule pb.ThreatRuleId) string {
	return "rule " + strings.TrimPrefix(rule.String(), "THREAT_RULE_ID_") + " unhealthy"
}

func reasonOr(resp *pb.GetSentryStatusResponse, fallback string) string {
	if r := resp.GetReason(); r != "" {
		return r
	}
	return fallback
}
