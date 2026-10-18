package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/threatdetect"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Process responder (#2636): turns a HIGH mining finding into the effective
// ProcessPolicy's action — ALERT (default), THROTTLE or FREEZE — records it
// in security_actions, and reverses it on operator release or when the TTL
// backstop fires. See docs/architecture/process-exec-guardrail.md,
// component 7.

// actionAuditResourceType is the audit_logs.resource_type for every apply,
// release, expiry and failure — category security.action per the design.
const actionAuditResourceType = "security.action"

// processActionSweepInterval is how often Run looks for expired actions.
const processActionSweepInterval = 60 * time.Second

// containerActuator is the slice of the Incus client the responder needs.
// An interface, not *incus.Client, so the responder is unit-testable with
// a fake; incusActuator adapts the real client.
type containerActuator interface {
	// CPULimit reads the box's current limits.cpu and limits.cpu.allowance
	// ("" when unset).
	CPULimit(name string) (count, allowance string, err error)
	// SetCPULimit writes both keys verbatim ("" unsets).
	SetCPULimit(name, count, allowance string) error
	Freeze(name string) error
	Unfreeze(name string) error
}

// incusActuator adapts *incus.Client to containerActuator.
type incusActuator struct{ c *incus.Client }

func (a incusActuator) CPULimit(name string) (string, string, error) {
	cfg, _, err := a.c.GetRawInstance(name)
	if err != nil {
		return "", "", err
	}
	return cfg["limits.cpu"], cfg["limits.cpu.allowance"], nil
}

func (a incusActuator) SetCPULimit(name, count, allowance string) error {
	return a.c.SetCPUConfig(name, count, allowance)
}

func (a incusActuator) Freeze(name string) error   { return a.c.FreezeContainer(name) }
func (a incusActuator) Unfreeze(name string) error { return a.c.UnfreezeContainer(name) }

// findingLifecycle is what the responder needs from a finding store:
// *threatdetect.FindingStore and *threatdetect.MemFindingStore both satisfy
// it.
type findingLifecycle interface {
	Upsert(ctx context.Context, f *threatdetect.Finding) (*threatdetect.Finding, error)
	Get(ctx context.Context, id int64) (*threatdetect.Finding, error)
	Resolve(ctx context.Context, id int64) (*threatdetect.Finding, error)
	SetResponse(ctx context.Context, id int64, r threatdetect.FindingResponse) (*threatdetect.Finding, error)
}

// ProcessResponder applies and releases process actions. One instance per
// daemon; apply/release are serialized so the open-row check and the Incus
// call cannot interleave for the same container. Audit entries go through
// the package's auditLogger (agent_server.go), satisfied by *audit.Store.
type ProcessResponder struct {
	policies *threatdetect.ProcessPolicyStore
	actions  threatdetect.ActionStore
	findings findingLifecycle
	act      containerActuator
	audit    auditLogger
	// degraded: the finding store has no Postgres, so a throttle's
	// previous-limit row could vanish on restart. The responder then applies
	// ALERT whatever the policy says (decided on #2641 Q2).
	degraded bool
	now      func() time.Time

	mu        sync.Mutex
	backendID string
}

// NewProcessResponder wires the responder. degraded forces ALERT-only.
func NewProcessResponder(policies *threatdetect.ProcessPolicyStore, actions threatdetect.ActionStore, findings findingLifecycle, act containerActuator, auditLog auditLogger, degraded bool) *ProcessResponder {
	return &ProcessResponder{
		policies: policies, actions: actions, findings: findings, act: act, audit: auditLog,
		degraded: degraded, now: time.Now,
	}
}

// Degraded reports whether responses are disabled for lack of persistence
// (GetSentryStatus surfaces it as "responses disabled").
func (r *ProcessResponder) Degraded() bool { return r.degraded }

// SetBackendID stamps the backend id onto the PROCESS_ACTION_EXPIRED
// findings the TTL sweep raises; same late-binding as Engine.SetBackendID.
func (r *ProcessResponder) SetBackendID(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.backendID = id
}

// OnFinding is called after every successful finding upsert (ActingSink).
// It acts only on an open HIGH finding from a mining rule with no action
// already open on its container, and returns the finding with its response
// recorded (nil when nothing changed).
func (r *ProcessResponder) OnFinding(ctx context.Context, f *threatdetect.Finding) *threatdetect.Finding {
	if f == nil || f.Container == "" || f.State != threatdetect.FindingStateOpen ||
		f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_HIGH || !threatdetect.RespondsTo(f.Rule) {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, err := r.actions.Open(ctx, f.Container); err == nil {
		return nil // one action per container; the open one stands
	} else if !errors.Is(err, threatdetect.ErrNoOpenAction) {
		log.Printf("[process-responder] finding %d on %s: read open action: %v", f.ID, f.Container, err)
		return nil
	}
	policy, err := r.policies.Effective(ctx, f.Container)
	if err != nil {
		// Unknown policy: do nothing rather than guess. The finding itself
		// is already recorded and delivered.
		log.Printf("[process-responder] finding %d on %s: read policy: %v", f.ID, f.Container, err)
		return nil
	}
	action := policy.GetAction()
	if r.degraded {
		action = pb.ProcessAction_PROCESS_ACTION_ALERT
	}
	now := r.now()
	detail := fmt.Sprintf("finding=%d rule=%s tenant=%s container=%s policy=%s", f.ID, f.Rule, f.TenantID, f.Container, policy.GetAction())

	switch action {
	case pb.ProcessAction_PROCESS_ACTION_THROTTLE, pb.ProcessAction_PROCESS_ACTION_FREEZE:
	default:
		if f.Response != nil && f.Response.Action == pb.ProcessAction_PROCESS_ACTION_ALERT && f.Response.State == pb.ResponseState_RESPONSE_STATE_NONE {
			return nil // a repeat of a finding already recorded as alert-only
		}
		if r.degraded {
			detail += " degraded=true"
		}
		out := r.setResponse(ctx, f.ID, threatdetect.FindingResponse{
			Action: pb.ProcessAction_PROCESS_ACTION_ALERT, State: pb.ResponseState_RESPONSE_STATE_NONE, AppliedAt: now,
		})
		r.auditLog(ctx, "alert", f.Container, detail)
		return out
	}

	row := &threatdetect.SecurityAction{
		FindingID: f.ID, Container: f.Container, TenantID: f.TenantID, Action: action,
		AppliedAt: now, ExpiresAt: now.Add(policy.GetTtl().AsDuration()),
	}
	if err := r.apply(row, policy.GetThrottleAllowance()); err != nil {
		return r.recordFailure(ctx, f, row, err, detail)
	}
	if err := r.actions.Insert(ctx, row); err != nil {
		// Applied but unrecorded: undo rather than leave a throttle no row
		// explains (and no release could find).
		if uerr := r.undo(row); uerr != nil {
			log.Printf("[process-responder] undo unrecorded %s on %s: %v", row.Action, row.Container, uerr)
		}
		return r.recordFailure(ctx, f, nil, fmt.Errorf("record action: %w", err), detail)
	}
	out := r.setResponse(ctx, f.ID, threatdetect.FindingResponse{
		Action: action, State: pb.ResponseState_RESPONSE_STATE_APPLIED, AppliedAt: now, ExpiresAt: row.ExpiresAt,
	})
	r.auditLog(ctx, "apply", fmt.Sprintf("%d", row.ID), fmt.Sprintf("%s action=%s prev_cpu=%q prev_allowance=%q allowance=%q expires_at=%s",
		detail, action, row.PrevCPUCount, row.PrevCPUAllowance, policy.GetThrottleAllowance(), row.ExpiresAt.UTC().Format(time.RFC3339)))
	log.Printf("[process-responder] %s applied to %s (finding %d, expires %s)", action, f.Container, f.ID, row.ExpiresAt.UTC().Format(time.RFC3339))
	return out
}

// recordFailure writes the failed row (released on insert so it never
// holds the open slot — the next re-fire is the retry) and marks the
// finding FAILED with the error. row may be nil when the failure was the
// insert itself.
func (r *ProcessResponder) recordFailure(ctx context.Context, f *threatdetect.Finding, row *threatdetect.SecurityAction, cause error, detail string) *threatdetect.Finding {
	action := pb.ProcessAction_PROCESS_ACTION_UNSPECIFIED
	if row != nil {
		action = row.Action
		row.Error = cause.Error()
		row.ReleasedAt, row.ReleasedBy = row.AppliedAt, threatdetect.ReleasedByError
		if err := r.actions.Insert(ctx, row); err != nil {
			log.Printf("[process-responder] record failed %s on %s: %v", row.Action, row.Container, err)
		}
	}
	if action == pb.ProcessAction_PROCESS_ACTION_UNSPECIFIED {
		if p, perr := r.policies.Effective(ctx, f.Container); perr == nil {
			action = p.GetAction()
		}
	}
	log.Printf("[process-responder] %s on %s (finding %d) FAILED: %v", action, f.Container, f.ID, cause)
	out := r.setResponse(ctx, f.ID, threatdetect.FindingResponse{
		Action: action, State: pb.ResponseState_RESPONSE_STATE_FAILED, AppliedAt: r.now(), Error: cause.Error(),
	})
	r.auditLog(ctx, "fail", f.Container, fmt.Sprintf("%s action=%s error=%q", detail, action, cause.Error()))
	return out
}

// apply performs the action on the box, filling row's previous-limit
// fields for THROTTLE.
func (r *ProcessResponder) apply(row *threatdetect.SecurityAction, allowance string) error {
	switch row.Action {
	case pb.ProcessAction_PROCESS_ACTION_THROTTLE:
		count, allow, err := r.act.CPULimit(row.Container)
		if err != nil {
			return fmt.Errorf("read cpu limit: %w", err)
		}
		row.PrevCPUCount, row.PrevCPUAllowance = count, allow
		if err := r.act.SetCPULimit(row.Container, count, allowance); err != nil {
			return fmt.Errorf("set cpu allowance %q: %w", allowance, err)
		}
		return nil
	case pb.ProcessAction_PROCESS_ACTION_FREEZE:
		if err := r.act.Freeze(row.Container); err != nil {
			return fmt.Errorf("freeze: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("action %s cannot be applied", row.Action)
	}
}

// undo reverses row's action: the recorded limit back, or unfreeze.
func (r *ProcessResponder) undo(row *threatdetect.SecurityAction) error {
	switch row.Action {
	case pb.ProcessAction_PROCESS_ACTION_THROTTLE:
		if err := r.act.SetCPULimit(row.Container, row.PrevCPUCount, row.PrevCPUAllowance); err != nil {
			return fmt.Errorf("restore cpu limit %q/%q: %w", row.PrevCPUCount, row.PrevCPUAllowance, err)
		}
		return nil
	case pb.ProcessAction_PROCESS_ACTION_FREEZE:
		if err := r.act.Unfreeze(row.Container); err != nil {
			return fmt.Errorf("unfreeze: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("action %s cannot be released", row.Action)
	}
}

// Release undoes the open action on container at an operator's request:
// restores the recorded limit or unfreezes, marks the row released by
// operator, records RELEASED on the finding and resolves it. Returns the
// finding (nil if its row is gone) and ErrNoOpenAction when nothing is
// open. A failed Incus call leaves the action open so the operator can
// retry.
func (r *ProcessResponder) Release(ctx context.Context, container string) (*threatdetect.Finding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, err := r.actions.Open(ctx, container)
	if err != nil {
		return nil, err
	}
	if err := r.undo(row); err != nil {
		return nil, fmt.Errorf("release %s on %s: %w", row.Action, container, err)
	}
	now := r.now()
	if err := r.actions.Release(ctx, row.ID, threatdetect.ReleasedByOperator, now); err != nil {
		return nil, err
	}
	f := r.setResponse(ctx, row.FindingID, threatdetect.FindingResponse{
		Action: row.Action, State: pb.ResponseState_RESPONSE_STATE_RELEASED,
		AppliedAt: row.AppliedAt, ExpiresAt: row.ExpiresAt, ReleasedAt: now, ReleasedBy: threatdetect.ReleasedByOperator,
	})
	resolved, rerr := r.findings.Resolve(ctx, row.FindingID)
	switch {
	case rerr == nil:
		f = resolved
	case errors.Is(rerr, threatdetect.ErrFindingNotOpen), errors.Is(rerr, threatdetect.ErrFindingNotFound):
		// Already resolved by hand, or gone from a degraded ring: the
		// release itself still happened.
	default:
		log.Printf("[process-responder] resolve finding %d after release: %v", row.FindingID, rerr)
	}
	r.auditLog(ctx, "release", fmt.Sprintf("%d", row.ID), fmt.Sprintf("finding=%d container=%s action=%s released_by=%s restored_cpu=%q restored_allowance=%q",
		row.FindingID, container, row.Action, threatdetect.ReleasedByOperator, row.PrevCPUCount, row.PrevCPUAllowance))
	log.Printf("[process-responder] %s released on %s by operator (finding %d)", row.Action, container, row.FindingID)
	return f, nil
}

// SweepExpired releases every action whose TTL passed and raises a MEDIUM
// PROCESS_ACTION_EXPIRED finding for each, so an unattended throttle never
// silently becomes permanent. Returns how many were released; a box Incus
// refuses to restore stays open and is retried next sweep.
func (r *ProcessResponder) SweepExpired(ctx context.Context, now time.Time) int {
	rows, err := r.actions.ListExpired(ctx, now)
	if err != nil {
		log.Printf("[process-responder] list expired actions: %v", err)
		return 0
	}
	released := 0
	for _, row := range rows {
		if err := r.expire(ctx, row, now); err != nil {
			log.Printf("[process-responder] expire %s on %s (action %d): %v", row.Action, row.Container, row.ID, err)
			continue
		}
		released++
	}
	return released
}

func (r *ProcessResponder) expire(ctx context.Context, row *threatdetect.SecurityAction, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.undo(row); err != nil {
		return err
	}
	if err := r.actions.Release(ctx, row.ID, threatdetect.ReleasedByTTL, now); err != nil {
		return err
	}
	r.setResponse(ctx, row.FindingID, threatdetect.FindingResponse{
		Action: row.Action, State: pb.ResponseState_RESPONSE_STATE_EXPIRED,
		AppliedAt: row.AppliedAt, ExpiresAt: row.ExpiresAt, ReleasedAt: now, ReleasedBy: threatdetect.ReleasedByTTL,
	})
	ttl := row.ExpiresAt.Sub(row.AppliedAt).Round(time.Second)
	note := fmt.Sprintf("%s on %s released by the TTL backstop after %s with no operator decision (finding %d); original limit restored",
		row.Action, row.Container, ttl, row.FindingID)
	if _, err := r.findings.Upsert(ctx, &threatdetect.Finding{
		Rule:      pb.ThreatRuleId_THREAT_RULE_ID_PROCESS_ACTION_EXPIRED,
		Severity:  pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM,
		TenantID:  row.TenantID,
		Container: row.Container,
		BackendID: r.backendID,
		Subject:   row.Container,
		Evidence:  threatdetect.Evidence{Configs: []threatdetect.ConfigEvidence{{Note: note}}},
	}); err != nil {
		log.Printf("[process-responder] raise PROCESS_ACTION_EXPIRED for %s: %v", row.Container, err)
	}
	r.auditLog(ctx, "expire", fmt.Sprintf("%d", row.ID), fmt.Sprintf("finding=%d container=%s action=%s released_by=%s ttl=%s",
		row.FindingID, row.Container, row.Action, threatdetect.ReleasedByTTL, ttl))
	log.Printf("[process-responder] %s on %s expired after %s; released (finding %d)", row.Action, row.Container, ttl, row.FindingID)
	return nil
}

// Run drives the TTL sweep every processActionSweepInterval until ctx ends.
func (r *ProcessResponder) Run(ctx context.Context) {
	ticker := time.NewTicker(processActionSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.SweepExpired(ctx, r.now())
		}
	}
}

func (r *ProcessResponder) setResponse(ctx context.Context, id int64, resp threatdetect.FindingResponse) *threatdetect.Finding {
	f, err := r.findings.SetResponse(ctx, id, resp)
	if err != nil {
		log.Printf("[process-responder] record response %s/%s on finding %d: %v", resp.Action, resp.State, id, err)
		return nil
	}
	return f
}

func (r *ProcessResponder) auditLog(ctx context.Context, action, resourceID, detail string) {
	if r.audit == nil {
		return
	}
	if err := r.audit.Log(ctx, &audit.AuditEntry{
		Action: action, ResourceType: actionAuditResourceType, ResourceID: resourceID, Detail: detail,
	}); err != nil {
		log.Printf("[process-responder] audit %s %s: %v", action, resourceID, err)
	}
}

// ActingSink wraps a FindingSink so every successful upsert — from the
// engine or any other writer — is offered to the responder. The engine
// never learns the difference.
type ActingSink struct {
	inner     threatdetect.FindingSink
	responder *ProcessResponder
}

// NewActingSink wraps inner with responder.
func NewActingSink(inner threatdetect.FindingSink, responder *ProcessResponder) *ActingSink {
	return &ActingSink{inner: inner, responder: responder}
}

// Upsert writes through inner, then lets the responder act. The finding
// returned carries the response the responder recorded, if any.
func (s *ActingSink) Upsert(ctx context.Context, f *threatdetect.Finding) (*threatdetect.Finding, error) {
	out, err := s.inner.Upsert(ctx, f)
	if err != nil || out == nil || s.responder == nil {
		return out, err
	}
	if acted := s.responder.OnFinding(ctx, out); acted != nil {
		return acted, nil
	}
	return out, nil
}
