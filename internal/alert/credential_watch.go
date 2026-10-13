package alert

import (
	"context"
	"encoding/json"
	"log"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Credential-expiry watch (#2371).
//
// GetSkillBoxCredentialStatus is pull-only: nothing told an operator when a
// skill box's device-code sign-in expired. The watcher below polls every
// provisioned skill box on a fixed interval, keeps each box's last-seen
// credential source in a CredentialStateStore (Postgres in the daemon, so a
// restart does not re-fire), and sends exactly one alert per flip INTO
// CODE_CREDENTIAL_SOURCE_EXPIRED through the operator's existing webhook.
//
// Nothing here ever handles a credential value: the probe behind
// CredentialProber reports a source NAME only (see
// internal/coderun/engine/credential_status.go), and the alert carries the
// box, the engine, and the two source names.

// CredentialWatchInterval is how often the daemon sweeps every skill box.
const CredentialWatchInterval = 15 * time.Minute

// CredentialExpiredAlertName is the alert name on the webhook payload and in
// the webhook_deliveries record.
const CredentialExpiredAlertName = "CodeCredentialExpired" // #nosec G101 -- an alert NAME, not a credential value

// credentialWatchDeliverySource is the webhook_deliveries.source value for
// deliveries from this watcher.
const credentialWatchDeliverySource = "credential-watch" // #nosec G101 -- a delivery-source label, not a credential value

// CredentialWatchTarget is one provisioned skill box to probe.
type CredentialWatchTarget struct {
	SkillID string
	// Box is the container the probe runs in.
	Box string
	// Engine is the coding engine whose sign-in is probed.
	Engine pb.AgentEngine
}

// CredentialProber lists the boxes to watch and probes one. Implemented by
// the daemon's AgentSkillServer, over the same probe
// GetSkillBoxCredentialStatus runs.
type CredentialProber interface {
	CredentialWatchTargets(ctx context.Context) ([]CredentialWatchTarget, error)
	ProbeCredential(ctx context.Context, t CredentialWatchTarget) (pb.CodeCredentialSource, error)
}

// CredentialStateStore persists each skill box's last-seen credential
// source, so "once per flip" survives a daemon restart.
type CredentialStateStore interface {
	// LastSeen returns the recorded source; ok=false when the skill has
	// never been observed.
	LastSeen(ctx context.Context, skillID string) (src pb.CodeCredentialSource, ok bool, err error)
	Record(ctx context.Context, skillID string, src pb.CodeCredentialSource, observedAt time.Time) error
}

// CredentialAlertNotifier delivers one expiry alert.
type CredentialAlertNotifier interface {
	NotifyCredentialExpired(ctx context.Context, a CredentialExpiredAlert)
}

// CredentialExpiredAlert is the payload for one flip into expired. Names
// only — there is no field a credential value could ride on.
type CredentialExpiredAlert struct {
	SkillID          string
	Box              string
	Engine           pb.AgentEngine
	CredentialSource pb.CodeCredentialSource
	// PreviousSource is UNSPECIFIED when the box had never been observed
	// before (first sweep after the box appeared, or after this watcher
	// was first deployed).
	PreviousSource pb.CodeCredentialSource
	ObservedAt     time.Time
}

// credentialExpiredWire is the JSON shape on the webhook: enums by name.
type credentialExpiredWire struct {
	Alert            string    `json:"alert"`
	SkillID          string    `json:"skill_id"`
	Box              string    `json:"box"`
	Engine           string    `json:"engine"`
	CredentialSource string    `json:"credential_source"`
	PreviousSource   string    `json:"previous_source"`
	ObservedAt       time.Time `json:"observed_at"`
}

// MarshalJSON renders the webhook payload.
func (a CredentialExpiredAlert) MarshalJSON() ([]byte, error) {
	return json.Marshal(credentialExpiredWire{
		Alert:            CredentialExpiredAlertName,
		SkillID:          a.SkillID,
		Box:              a.Box,
		Engine:           a.Engine.String(),
		CredentialSource: a.CredentialSource.String(),
		PreviousSource:   a.PreviousSource.String(),
		ObservedAt:       a.ObservedAt.UTC(),
	})
}

// CredentialWatcher runs the sweep. Construct with NewCredentialWatcher.
type CredentialWatcher struct {
	prober   CredentialProber
	state    CredentialStateStore
	notifier CredentialAlertNotifier
	interval time.Duration
	now      func() time.Time

	cancel context.CancelFunc // set by Start
	done   chan struct{}      // closed when the Start loop exits
}

// NewCredentialWatcher builds a watcher sweeping every
// CredentialWatchInterval. All three dependencies are required.
func NewCredentialWatcher(prober CredentialProber, state CredentialStateStore, notifier CredentialAlertNotifier) *CredentialWatcher {
	return &CredentialWatcher{
		prober:   prober,
		state:    state,
		notifier: notifier,
		interval: CredentialWatchInterval,
		now:      time.Now,
	}
}

// Start sweeps once now, then every interval, until ctx is done or Stop is
// called. Call once.
func (w *CredentialWatcher) Start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)
	w.done = make(chan struct{})
	go func() {
		defer close(w.done)
		w.Sweep(ctx)
		t := time.NewTicker(w.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				w.Sweep(ctx)
			}
		}
	}()
}

// Stop ends the sweep loop and waits for it to exit. Safe before Start.
func (w *CredentialWatcher) Stop() {
	if w.cancel == nil {
		return
	}
	w.cancel()
	<-w.done
}

// Sweep probes every target once and returns how many alerts it sent.
//
// Per target: a probe error, or a state-store read error, skips the target
// without touching its state. The new source is recorded BEFORE any alert
// is sent; if recording fails no alert goes out this sweep, so a failing
// store can delay an alert by one sweep but never repeat it.
func (w *CredentialWatcher) Sweep(ctx context.Context) int {
	targets, err := w.prober.CredentialWatchTargets(ctx)
	if err != nil {
		log.Printf("[credential-watch] list skill boxes: %v", err)
		return 0
	}
	fired := 0
	for _, t := range targets {
		if ctx.Err() != nil {
			return fired
		}
		cur, perr := w.prober.ProbeCredential(ctx, t)
		if perr != nil {
			log.Printf("[credential-watch] probe %s: %v", t.Box, perr)
			continue
		}
		prev, seen, serr := w.state.LastSeen(ctx, t.SkillID)
		if serr != nil {
			log.Printf("[credential-watch] read last-seen state for skill %s: %v", t.SkillID, serr)
			continue
		}
		if seen && prev == cur {
			continue
		}
		now := w.now()
		if rerr := w.state.Record(ctx, t.SkillID, cur, now); rerr != nil {
			log.Printf("[credential-watch] record state for skill %s: %v", t.SkillID, rerr)
			continue
		}
		if cur != pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_EXPIRED {
			continue
		}
		if !seen {
			prev = pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_UNSPECIFIED
		}
		w.notifier.NotifyCredentialExpired(ctx, CredentialExpiredAlert{
			SkillID:          t.SkillID,
			Box:              t.Box,
			Engine:           t.Engine,
			CredentialSource: cur,
			PreviousSource:   prev,
			ObservedAt:       now,
		})
		fired++
	}
	return fired
}
