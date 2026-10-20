package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
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

// processResponseQueue is the depth of the responder's work queue (#2638
// review). The async ActingSink hands each upsert to it so the responder's
// Incus calls (the kill's init-pid read, throttle, freeze) never run on the
// goroutine that wrote the finding — for a signature finding that is the
// exec ring consumer. A full queue drops the job (counted, logged, and
// audited by the worker) rather than blocking that goroutine.
const processResponseQueue = 256

// processActionRetryBackoff is how long after a FAILED apply the responder
// leaves the container alone instead of retrying on every rule re-fire.
const processActionRetryBackoff = 10 * time.Minute

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
	// killer SIGKILLs a matched process for kill_process (#2638); nil
	// disables the kill whatever the policy says.
	killer processKiller

	// queue feeds the worker started by Run (async ActingSink only).
	queue   chan responseJob
	dropped atomic.Uint64
	// droppedAudited is the dropped count the worker last wrote an audit
	// row for; touched only by the worker goroutine.
	droppedAudited uint64

	// pendingMu guards pending: the queued or in-flight jobs per finding and
	// container. A miner-signature finding is keyed per tenant and pattern, so
	// two boxes of one tenant can share it (#2766); Release on one box leaves
	// the shared finding open while another box still has a response waiting
	// on it (an action already applied on another box is read from the
	// store, not from here). A separate lock from mu because enqueue runs on
	// the writer's goroutine and must never wait behind a Release's Incus
	// call.
	pendingMu sync.Mutex
	pending   map[int64]map[string]int

	// afterQueuedRead, when set, runs in runJob right before the locked
	// staleness read. Test seam only: it lets a test land a release or
	// resolve after the job was queued and before the worker reads it.
	afterQueuedRead func()

	mu        sync.Mutex
	backendID string
}

// NewProcessResponder wires the responder. degraded forces ALERT-only.
func NewProcessResponder(policies *threatdetect.ProcessPolicyStore, actions threatdetect.ActionStore, findings findingLifecycle, act containerActuator, auditLog auditLogger, degraded bool) *ProcessResponder {
	return &ProcessResponder{
		policies: policies, actions: actions, findings: findings, act: act, audit: auditLog,
		degraded: degraded, now: time.Now,
		queue:   make(chan responseJob, processResponseQueue),
		pending: map[int64]map[string]int{},
	}
}

// respondable reports whether the responder could act on f at all: an open
// HIGH finding from a mining rule, attributed to a container.
func respondable(f *threatdetect.Finding) bool {
	return f != nil && f.Container != "" && f.State == threatdetect.FindingStateOpen &&
		f.Severity == pb.ThreatSeverity_THREAT_SEVERITY_HIGH && threatdetect.RespondsTo(f.Rule)
}

// responseJob is one finding handed to the worker, with the exec a kill
// would target.
type responseJob struct {
	f      *threatdetect.Finding
	target *threatdetect.ExecEvidence
	// at is when the job was queued: a release stamped at or after it means
	// an operator (or the TTL backstop) decided after this response was
	// asked for, and the job must not undo that decision. Truncated to the
	// microsecond, the precision Postgres stores released_at at, so a
	// release in the same microsecond still counts as at-or-after.
	at time.Time
}

// enqueue offers a job to the worker without ever blocking the caller.
func (r *ProcessResponder) enqueue(f *threatdetect.Finding, target *threatdetect.ExecEvidence) bool {
	cp := *f
	job := responseJob{f: &cp, at: r.now().Truncate(time.Microsecond)}
	if target != nil {
		t := *target
		job.target = &t
	}
	r.trackPending(f.ID, f.Container, 1)
	select {
	case r.queue <- job:
		return true
	default:
		r.trackPending(f.ID, f.Container, -1)
		if n := r.dropped.Add(1); n == 1 || n%100 == 0 {
			log.Printf("[process-responder] work queue full (cap %d): dropped response for finding %d on %s (%d dropped so far)",
				processResponseQueue, f.ID, f.Container, n)
		}
		return false
	}
}

// trackPending adds delta to the queued-or-in-flight job count for finding id
// on container.
func (r *ProcessResponder) trackPending(id int64, container string, delta int) {
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()
	byBox := r.pending[id]
	if byBox == nil {
		if delta <= 0 {
			return
		}
		byBox = map[string]int{}
		r.pending[id] = byBox
	}
	byBox[container] += delta
	if byBox[container] <= 0 {
		delete(byBox, container)
	}
	if len(byBox) == 0 {
		delete(r.pending, id)
	}
}

// pendingElsewhere reports whether finding id has a queued or in-flight job
// for a container other than container.
func (r *ProcessResponder) pendingElsewhere(id int64, container string) bool {
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()
	for box, n := range r.pending[id] {
		if box != container && n > 0 {
			return true
		}
	}
	return false
}

// DroppedResponses counts findings the responder never acted on because its
// queue was full.
func (r *ProcessResponder) DroppedResponses() uint64 { return r.dropped.Load() }

// runQueue is the worker: it acts on queued findings one at a time, so the
// Incus work happens here and never on the writer's goroutine.
func (r *ProcessResponder) runQueue(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-r.queue:
			r.runJob(ctx, job)
			r.auditDrops(ctx)
		}
	}
}

// runJob acts on one queued job, but only if it is still current. The queued
// copy of the finding was taken when the rule fired; by the time the worker
// gets to it an operator may have released the box's action, the sentry or
// an operator may have resolved the finding, or the TTL backstop may have
// released the action. Acting on the stale copy would re-throttle a box the
// operator just released, write APPLIED onto a resolved finding, or kill a
// process whose finding an operator just closed. So the finding and the
// box's own action row are read under r.mu right before the kill (readJob,
// one read for both) and the result is what the job then acts on; they are
// read once more under r.mu after the kill, because the kill runs without
// the lock. A stale job is skipped and audited as "response-skipped". A
// release counts only on the job's own container and only for this
// finding: a miner-signature finding can be shared by several boxes of one
// tenant, and releasing one of them says nothing about the others; a box
// can also carry a release for a different finding (#2766). A store read
// that fails is not a reason to skip: the job is not stale as far as anyone
// can tell, so it goes on (the locked read retries once).
//
// Whatever the job did, settle then checks whether it was the last thing
// holding a finding open that an operator already released on another box.
func (r *ProcessResponder) runJob(ctx context.Context, job responseJob) {
	var out *threatdetect.Finding
	defer func() {
		r.trackPending(job.f.ID, job.f.Container, -1)
		r.settle(ctx, job, out)
	}()
	if r.afterQueuedRead != nil {
		r.afterQueuedRead()
	}
	out = r.onFindingChecked(ctx, job.f, job.target, func() (*threatdetect.Finding, string) {
		v := r.readJob(ctx, job)
		if v.err != nil {
			log.Printf("[process-responder] finding %d on %s: read for queued response: %v; reading again", job.f.ID, job.f.Container, v.err)
			v = r.readJob(ctx, job)
		}
		reason := v.stale(job)
		switch {
		case reason != "":
			r.auditSkip(ctx, job, reason)
		case v.err != nil:
			log.Printf("[process-responder] finding %d on %s: read for queued response failed twice (%v); acting on the queued copy", job.f.ID, job.f.Container, v.err)
		}
		return v.current(job), reason
	})
}

// jobView is one read of what a queued job depends on: the finding as the
// store has it now, and the job's own box's latest action row for that
// finding (a box's row for another finding says nothing about this one).
// A half whose read failed is nil with the error in err: the view is then
// inconclusive, not stale, and the caller decides whether to read again or
// go on with the queued copy.
type jobView struct {
	finding *threatdetect.Finding
	// gone: the store has no such finding any more (definite).
	gone bool
	last *threatdetect.SecurityAction
	err  error
}

// readJob reads a jobView. The finding keeps the job's container: the
// store's row may carry the first container that opened it, and the action
// belongs to the box whose exec fired.
func (r *ProcessResponder) readJob(ctx context.Context, job responseJob) jobView {
	var v jobView
	f, err := r.findings.Get(ctx, job.f.ID)
	switch {
	case errors.Is(err, threatdetect.ErrFindingNotFound):
		v.gone = true
	case err != nil:
		v.err = fmt.Errorf("finding: %w", err)
	default:
		cp := *f
		cp.Container = job.f.Container
		v.finding = &cp
	}
	rows, err := r.actions.ListByFinding(ctx, job.f.ID)
	if err != nil {
		v.err = errors.Join(v.err, fmt.Errorf("actions: %w", err))
		return v
	}
	for _, row := range rows { // newest first
		if row.Container == job.f.Container {
			v.last = row
			break
		}
	}
	return v
}

// stale is the definite reason the job must not run: the finding is gone
// or no longer open, or the job's own container had its action for this
// finding released at or after the job was queued. A failed apply (released
// by "error") is not a decision and does not count. "" when the job may
// run, including when the view is inconclusive.
func (v jobView) stale(job responseJob) string {
	switch {
	case v.gone:
		return "finding no longer exists"
	case v.finding != nil && v.finding.State != threatdetect.FindingStateOpen:
		return "finding no longer open"
	case v.last != nil && !v.last.ReleasedAt.IsZero() && v.last.ReleasedBy != threatdetect.ReleasedByError && !v.last.ReleasedAt.Before(job.at):
		return "action on " + job.f.Container + " released by " + v.last.ReleasedBy + " after the response was queued"
	}
	return ""
}

// current is the finding the job acts on: the fresh read, or the queued
// copy when the finding could not be read.
func (v jobView) current(job responseJob) *threatdetect.Finding {
	if v.finding != nil {
		return v.finding
	}
	cp := *job.f
	return &cp
}

// settle runs after every queued job (#2766 review). A job that ends with no
// action standing on its box — an ALERT policy or override, a degraded
// backend, a policy read error, a failed apply, or a skip — may have been
// the one thing holding a finding open: Release leaves a shared finding
// open while another box's job is queued or in flight. Once nothing else
// holds it (no open action on any box, no other queued job), a finding an
// operator already released is resolved here, as that release would have
// resolved it had the job not been queued. A finding never released is
// left alone: an alert-only finding stays open for the operator as it
// always has.
func (r *ProcessResponder) settle(ctx context.Context, job responseJob, out *threatdetect.Finding) {
	if out != nil && out.Response != nil && out.Response.State == pb.ResponseState_RESPONSE_STATE_APPLIED {
		return // an action stands on the job's box
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rows, err := r.actions.ListByFinding(ctx, job.f.ID)
	if err != nil {
		log.Printf("[process-responder] finding %d: list actions after queued response on %s: %v", job.f.ID, job.f.Container, err)
		return
	}
	released := false
	for _, row := range rows {
		if row.Open() {
			return // an action still stands somewhere: the finding stays open
		}
		released = released || row.ReleasedBy == threatdetect.ReleasedByOperator
	}
	if !released || r.pendingElsewhere(job.f.ID, "") {
		return
	}
	_, rerr := r.findings.Resolve(ctx, job.f.ID)
	switch {
	case rerr == nil:
		r.auditLog(ctx, "resolve", job.f.Container, fmt.Sprintf("finding=%d container=%s reason=%q",
			job.f.ID, job.f.Container, "released by operator on another box; the last queued response ended without an action"))
		log.Printf("[process-responder] finding %d resolved: released by operator earlier, and the last queued response (on %s) ended without an action", job.f.ID, job.f.Container)
	case errors.Is(rerr, threatdetect.ErrFindingNotOpen), errors.Is(rerr, threatdetect.ErrFindingNotFound):
	default:
		log.Printf("[process-responder] resolve finding %d after queued response on %s: %v", job.f.ID, job.f.Container, rerr)
	}
}

func (r *ProcessResponder) auditSkip(ctx context.Context, job responseJob, reason string) {
	r.auditLog(ctx, "response-skipped", job.f.Container, fmt.Sprintf("finding=%d rule=%s tenant=%s container=%s queued_at=%s reason=%q",
		job.f.ID, job.f.Rule, job.f.TenantID, job.f.Container, job.at.UTC().Format(time.RFC3339Nano), reason))
	log.Printf("[process-responder] queued response for finding %d on %s skipped: %s", job.f.ID, job.f.Container, reason)
}

// auditDrops writes one audit row per batch of newly dropped responses, so a
// drop is visible in the trail and not only in the log. Worker goroutine only.
func (r *ProcessResponder) auditDrops(ctx context.Context) {
	n := r.dropped.Load()
	if n == r.droppedAudited {
		return
	}
	r.auditLog(ctx, "response-dropped", "queue", fmt.Sprintf("dropped=%d total_dropped=%d queue_cap=%d",
		n-r.droppedAudited, n, processResponseQueue))
	r.droppedAudited = n
}

// SetProcessKiller wires the host-side kill used by kill_process (#2638).
// Call before the responder sees findings.
func (r *ProcessResponder) SetProcessKiller(k processKiller) { r.killer = k }

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
	return r.onFinding(ctx, f, lastExec(f))
}

// lastExec is the newest exec on f's evidence, nil when it carries none.
func lastExec(f *threatdetect.Finding) *threatdetect.ExecEvidence {
	if f == nil || len(f.Evidence.Execs) == 0 {
		return nil
	}
	return &f.Evidence.Execs[len(f.Evidence.Execs)-1]
}

// onFinding is OnFinding with the exec a kill targets given explicitly: the
// ActingSink passes the exec of the write that triggered this call, which is
// the process that just matched, independent of how the store merged or
// capped the stored evidence.
func (r *ProcessResponder) onFinding(ctx context.Context, f *threatdetect.Finding, target *threatdetect.ExecEvidence) *threatdetect.Finding {
	return r.onFindingChecked(ctx, f, target, nil)
}

// onFindingChecked is onFinding with an optional recheck run under r.mu
// before anything that touches the box — the kill as much as the policy
// action. recheck returns the finding as the store has it now (what the
// rest of the response acts on) and a non-empty reason when the job is
// stale, which aborts (the queued-job path, see runJob).
func (r *ProcessResponder) onFindingChecked(ctx context.Context, f *threatdetect.Finding, target *threatdetect.ExecEvidence, recheck func() (*threatdetect.Finding, string)) *threatdetect.Finding {
	if !respondable(f) {
		return nil
	}
	// kill_process (#2638) is additive and per process: it runs for every
	// matched exec, before and independent of the one-action-per-container
	// policy action below, which still applies. It needs no responder state,
	// so it runs outside the lock: its Incus read never holds up a release.
	// But a queued job is rechecked under r.mu first (#2638 review): a
	// Release or resolve that landed while the job waited takes r.mu, so once
	// the recheck passes under it no release is in flight, and a finding an
	// operator already closed is never the reason a process dies.
	if recheck != nil {
		cur, stale := r.stale(recheck)
		if stale {
			return nil
		}
		f = cur
	}
	killedPID := r.maybeKill(ctx, f, target)

	r.mu.Lock()
	defer r.mu.Unlock()
	if recheck != nil {
		cur, reason := recheck()
		if reason != "" {
			if killedPID == 0 {
				return nil
			}
			// Released or resolved during the kill itself (after the recheck
			// above let go of r.mu). The policy action is off, but the
			// process is dead and the trail must say so: set process_killed
			// on whatever response the release wrote, not on the pre-kill
			// copy.
			return r.recordKill(ctx, cur, killedPID)
		}
		f = cur
	}
	killed := killedPID != 0 || (f.Response != nil && f.Response.ProcessKilled)

	if _, err := r.actions.Open(ctx, f.Container); err == nil {
		// One action per container; the open one stands.
		return r.recordKill(ctx, f, killedPID)
	} else if !errors.Is(err, threatdetect.ErrNoOpenAction) {
		log.Printf("[process-responder] finding %d on %s: read open action: %v", f.ID, f.Container, err)
		return r.recordKill(ctx, f, killedPID)
	}
	if last, err := r.actions.Latest(ctx, f.Container); err == nil &&
		last.ReleasedBy == threatdetect.ReleasedByError && r.now().Sub(last.AppliedAt) < processActionRetryBackoff {
		// The last apply failed moments ago: re-firing would only write
		// another error row. Say so once, on the first suppressed re-fire.
		if f.Response == nil || f.Response.State != pb.ResponseState_RESPONSE_STATE_FAILED {
			log.Printf("[process-responder] finding %d on %s: last %s failed at %s; not retrying for %s",
				f.ID, f.Container, last.Action, last.AppliedAt.UTC().Format(time.RFC3339), processActionRetryBackoff)
		}
		return r.recordKill(ctx, f, killedPID)
	}
	policy, err := r.policies.Effective(ctx, f.Container)
	if err != nil {
		// Unknown policy: no policy action rather than guess. The finding
		// itself is already recorded and delivered; a kill that already ran
		// is still recorded.
		log.Printf("[process-responder] finding %d on %s: read policy: %v", f.ID, f.Container, err)
		return r.recordKill(ctx, f, killedPID)
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
		if killedPID == 0 && f.Response != nil && f.Response.Action == pb.ProcessAction_PROCESS_ACTION_ALERT && f.Response.State == pb.ResponseState_RESPONSE_STATE_NONE {
			return nil // a repeat of a finding already recorded as alert-only
		}
		if r.degraded {
			detail += " degraded=true"
		}
		out := r.setResponse(ctx, f.ID, threatdetect.FindingResponse{
			Action: pb.ProcessAction_PROCESS_ACTION_ALERT, State: pb.ResponseState_RESPONSE_STATE_NONE, AppliedAt: now,
			ProcessKilled: killed,
		})
		r.auditLog(ctx, "alert", f.Container, detail)
		return out
	}

	row := &threatdetect.SecurityAction{
		FindingID: f.ID, Container: f.Container, TenantID: f.TenantID, Action: action,
		AppliedAt: now, ExpiresAt: now.Add(policy.GetTtl().AsDuration()), KilledPID: killedPID,
	}
	// Record first, act second: the row (with the previous limits a
	// THROTTLE restores) exists before the box is touched, so a crash
	// between the two leaves a PENDING row the sweep can undo.
	if action == pb.ProcessAction_PROCESS_ACTION_THROTTLE {
		count, allow, err := r.act.CPULimit(row.Container)
		if err != nil {
			return r.recordFailure(ctx, f, row, fmt.Errorf("read cpu limit: %w", err), detail, killed)
		}
		row.PrevCPUCount, row.PrevCPUAllowance = count, allow
	}
	row.Pending = true
	if err := r.actions.Insert(ctx, row); err != nil {
		return r.recordFailure(ctx, f, nil, fmt.Errorf("record action: %w", err), detail, killed)
	}
	if err := r.apply(row, policy.GetThrottleAllowance()); err != nil {
		return r.recordFailure(ctx, f, row, err, detail, killed)
	}
	if err := r.actions.MarkApplied(ctx, row.ID); err != nil {
		log.Printf("[process-responder] confirm %s on %s (action %d): %v", row.Action, row.Container, row.ID, err)
	}
	row.Pending = false
	out := r.setResponse(ctx, f.ID, threatdetect.FindingResponse{
		Action: action, State: pb.ResponseState_RESPONSE_STATE_APPLIED, AppliedAt: now, ExpiresAt: row.ExpiresAt,
		ProcessKilled: killed,
	})
	r.auditLog(ctx, "apply", fmt.Sprintf("%d", row.ID), fmt.Sprintf("%s action=%s prev_cpu=%q prev_allowance=%q allowance=%q expires_at=%s",
		detail, action, row.PrevCPUCount, row.PrevCPUAllowance, policy.GetThrottleAllowance(), row.ExpiresAt.UTC().Format(time.RFC3339)))
	log.Printf("[process-responder] %s applied to %s (finding %d, expires %s)", action, f.Container, f.ID, row.ExpiresAt.UTC().Format(time.RFC3339))
	return out
}

// stale runs recheck under r.mu and reports whether the job it guards is no
// longer current, with the finding as read. Takes and releases the lock
// itself so the caller's next step (the kill's Incus read) runs without it.
func (r *ProcessResponder) stale(recheck func() (*threatdetect.Finding, string)) (*threatdetect.Finding, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, reason := recheck()
	return cur, reason != ""
}

// maybeKill is the kill_process step (#2638): for a miner-signature finding
// whose effective policy sets kill_process, SIGKILL the process of the exec
// that just matched (target) after the killer re-checks its
// cgroup against the container. Every attempt is audited — "kill" naming the
// pid, or "kill-skipped" with the reason (pid reused, already exited, ...).
// Returns the killed pid, 0 when nothing was killed. Off on a degraded
// backend like every other response (decided on #2641 Q2). Called without
// r.mu.
func (r *ProcessResponder) maybeKill(ctx context.Context, f *threatdetect.Finding, target *threatdetect.ExecEvidence) uint32 {
	if r.killer == nil || !threatdetect.KillsProcess(f.Rule) || target == nil || target.PID == 0 || r.degraded {
		return 0
	}
	policy, err := r.policies.Effective(ctx, f.Container)
	if err != nil {
		log.Printf("[process-responder] finding %d on %s: read policy for kill: %v", f.ID, f.Container, err)
		r.auditLog(ctx, "kill-skipped", f.Container, fmt.Sprintf("finding=%d rule=%s tenant=%s container=%s pid=%d kill_skipped=%q",
			f.ID, f.Rule, f.TenantID, f.Container, target.PID, "read policy: "+err.Error()))
		return 0
	}
	if !policy.GetKillProcess() {
		return 0
	}
	ex := *target
	detail := fmt.Sprintf("finding=%d rule=%s tenant=%s container=%s pid=%d comm=%q filename=%q matched=%q",
		f.ID, f.Rule, f.TenantID, f.Container, ex.PID, ex.Comm, ex.Filename, ex.Matched)
	if err := r.killer.KillInContainer(f.Container, ex.PID); err != nil {
		r.auditLog(ctx, "kill-skipped", f.Container, fmt.Sprintf("%s kill_skipped=%q", detail, err.Error()))
		log.Printf("[process-responder] kill pid %d on %s (finding %d) skipped: %v", ex.PID, f.Container, f.ID, err)
		return 0
	}
	r.auditLog(ctx, "kill", f.Container, detail)
	log.Printf("[process-responder] SIGKILL pid %d (%s) on %s (finding %d, %s)", ex.PID, ex.Comm, f.Container, f.ID, ex.Matched)
	return ex.PID
}

// recordKill records a kill on a finding the policy action leaves alone
// (another action already open, or a failed apply backing off): the stored
// response is kept and only process_killed is set. nil when nothing was
// killed.
func (r *ProcessResponder) recordKill(ctx context.Context, f *threatdetect.Finding, killedPID uint32) *threatdetect.Finding {
	if killedPID == 0 {
		return nil
	}
	resp := threatdetect.FindingResponse{
		Action: pb.ProcessAction_PROCESS_ACTION_ALERT, State: pb.ResponseState_RESPONSE_STATE_NONE, AppliedAt: r.now(),
	}
	if f.Response != nil {
		resp = *f.Response
	}
	resp.ProcessKilled = true
	return r.setResponse(ctx, f.ID, resp)
}

// recordFailure writes the failed row (released on insert so it never
// holds the open slot — the next re-fire is the retry) and marks the
// finding FAILED with the error. row may be nil when the failure was the
// insert itself.
func (r *ProcessResponder) recordFailure(ctx context.Context, f *threatdetect.Finding, row *threatdetect.SecurityAction, cause error, detail string, killed bool) *threatdetect.Finding {
	action := pb.ProcessAction_PROCESS_ACTION_UNSPECIFIED
	if row != nil {
		action = row.Action
		row.Error = cause.Error()
		var err error
		if row.ID != 0 {
			err = r.actions.Fail(ctx, row.ID, row.Error, r.now())
		} else {
			// Failed before any row existed: record it released on insert
			// so it never holds the open slot.
			row.ReleasedAt, row.ReleasedBy = row.AppliedAt, threatdetect.ReleasedByError
			err = r.actions.Insert(ctx, row)
		}
		if err != nil {
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
		ProcessKilled: killed,
	})
	r.auditLog(ctx, "fail", f.Container, fmt.Sprintf("%s action=%s error=%q", detail, action, cause.Error()))
	return out
}

// apply performs the action on the box; a THROTTLE's previous limits are
// already on row.
func (r *ProcessResponder) apply(row *threatdetect.SecurityAction, allowance string) error {
	switch row.Action {
	case pb.ProcessAction_PROCESS_ACTION_THROTTLE:
		hard, err := threatdetect.HardThrottleAllowance(allowance, row.PrevCPUAllowance)
		if err != nil {
			return fmt.Errorf("throttle allowance: %w", err)
		}
		if err := r.act.SetCPULimit(row.Container, row.PrevCPUCount, hard); err != nil {
			return fmt.Errorf("set cpu allowance %q: %w", hard, err)
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
// operator, records RELEASED on the finding and resolves it. A finding
// another box still holds (a shared miner-signature finding, #2766: an
// action still open on that box, or a response queued or in flight for it)
// is left open, so releasing this box does not cancel that box's response;
// it is resolved when the last box is released (or, if the last box's
// queued response ends without an action, by that response: see settle).
// keptOpen reports which happened. Returns the finding (nil if its row is
// gone) and ErrNoOpenAction when nothing is open. A failed Incus call
// leaves the action open so the operator can retry.
//
// The release record carries this box's own kill (the row's killed_pid);
// a kill recorded by another path or another box of the finding stays on
// the finding because the store keeps process_killed once set.
func (r *ProcessResponder) Release(ctx context.Context, container string) (f *threatdetect.Finding, keptOpen bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, err := r.actions.Open(ctx, container)
	if err != nil {
		return nil, false, err
	}
	if err := r.undo(row); err != nil {
		return nil, false, fmt.Errorf("release %s on %s: %w", row.Action, container, err)
	}
	now := r.now()
	if err := r.actions.Release(ctx, row.ID, threatdetect.ReleasedByOperator, now); err != nil {
		return nil, false, err
	}
	f = r.setResponse(ctx, row.FindingID, threatdetect.FindingResponse{
		Action: row.Action, State: pb.ResponseState_RESPONSE_STATE_RELEASED,
		AppliedAt: row.AppliedAt, ExpiresAt: row.ExpiresAt, ReleasedAt: now, ReleasedBy: threatdetect.ReleasedByOperator,
		ProcessKilled: row.KilledPID != 0,
	})
	var rerr error
	var resolved *threatdetect.Finding
	keptOpen, holder := r.heldElsewhere(ctx, row.FindingID, container)
	if keptOpen {
		log.Printf("[process-responder] finding %d left open after release on %s: %s", row.FindingID, container, holder)
	} else {
		resolved, rerr = r.findings.Resolve(ctx, row.FindingID)
	}
	switch {
	case keptOpen:
	case rerr == nil:
		f = resolved
	case errors.Is(rerr, threatdetect.ErrFindingNotOpen), errors.Is(rerr, threatdetect.ErrFindingNotFound):
		// Already resolved by hand, or gone from a degraded ring: the
		// release itself still happened.
	default:
		log.Printf("[process-responder] resolve finding %d after release: %v", row.FindingID, rerr)
	}
	r.auditLog(ctx, "release", fmt.Sprintf("%d", row.ID), fmt.Sprintf("finding=%d container=%s action=%s released_by=%s restored_cpu=%q restored_allowance=%q finding_kept_open=%t",
		row.FindingID, container, row.Action, threatdetect.ReleasedByOperator, row.PrevCPUCount, row.PrevCPUAllowance, keptOpen))
	log.Printf("[process-responder] %s released on %s by operator (finding %d)", row.Action, container, row.FindingID)
	return f, keptOpen, nil
}

// heldElsewhere reports whether finding id is still held by a box other
// than container after container's action was released: an action still
// open on another box (read from the store, so an applied action counts
// whether or not this process queued it), or a response queued or in
// flight for another box. holder names it for the log. When the store
// cannot be read the finding is not held: a release that then turns out to
// be too early still happens, and a later release on the other box
// tolerates an already-resolved finding.
func (r *ProcessResponder) heldElsewhere(ctx context.Context, id int64, container string) (held bool, holder string) {
	rows, err := r.actions.ListByFinding(ctx, id)
	if err != nil {
		log.Printf("[process-responder] finding %d: list actions after release on %s: %v", id, container, err)
	}
	for _, row := range rows {
		if row.Open() && row.Container != container {
			return true, "an action is still open on " + row.Container
		}
	}
	if r.pendingElsewhere(id, container) {
		return true, "another box has a response queued"
	}
	return false, ""
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
	released := r.sweepOrphans(ctx, now)
	for _, row := range rows {
		done, err := r.expire(ctx, row, now)
		if err != nil {
			log.Printf("[process-responder] expire %s on %s (action %d): %v", row.Action, row.Container, row.ID, err)
			continue
		}
		if done {
			released++
		}
	}
	return released
}

func (r *ProcessResponder) expire(ctx context.Context, row *threatdetect.SecurityAction, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stillOpen(ctx, row) {
		return false, nil // released or superseded since the sweep listed it
	}
	if err := r.undo(row); err != nil {
		return false, err
	}
	if err := r.actions.Release(ctx, row.ID, threatdetect.ReleasedByTTL, now); err != nil {
		return false, err
	}
	r.setResponse(ctx, row.FindingID, threatdetect.FindingResponse{
		Action: row.Action, State: pb.ResponseState_RESPONSE_STATE_EXPIRED,
		AppliedAt: row.AppliedAt, ExpiresAt: row.ExpiresAt, ReleasedAt: now, ReleasedBy: threatdetect.ReleasedByTTL,
		ProcessKilled: row.KilledPID != 0, // the store keeps a kill recorded by another path
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
	return true, nil
}

// stillOpen re-reads the container's open action under the lock: the sweep
// listed row before taking it, and an operator release or a fresh apply may
// have landed in between. Only the very row that was listed may be undone.
// Caller holds r.mu.
func (r *ProcessResponder) stillOpen(ctx context.Context, row *threatdetect.SecurityAction) bool {
	cur, err := r.actions.Open(ctx, row.Container)
	return err == nil && cur.ID == row.ID
}

// sweepOrphans undoes PENDING rows older than PendingOrphanAfter: the daemon
// died between recording the action and confirming it. Undoing what was
// recorded is safe even if the box was never touched (the previous limits
// are written back unchanged). Returns how many it released.
func (r *ProcessResponder) sweepOrphans(ctx context.Context, now time.Time) int {
	rows, err := r.actions.ListOrphaned(ctx, now.Add(-threatdetect.PendingOrphanAfter))
	if err != nil {
		log.Printf("[process-responder] list orphaned actions: %v", err)
		return 0
	}
	n := 0
	for _, row := range rows {
		if err := r.reapOrphan(ctx, row, now); err != nil {
			log.Printf("[process-responder] orphan %s on %s (action %d): %v", row.Action, row.Container, row.ID, err)
			continue
		}
		n++
	}
	return n
}

func (r *ProcessResponder) reapOrphan(ctx context.Context, row *threatdetect.SecurityAction, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stillOpen(ctx, row) {
		return nil
	}
	if err := r.undo(row); err != nil {
		return err
	}
	if err := r.actions.Release(ctx, row.ID, threatdetect.ReleasedByOrphanSweep, now); err != nil {
		return err
	}
	r.setResponse(ctx, row.FindingID, threatdetect.FindingResponse{
		Action: row.Action, State: pb.ResponseState_RESPONSE_STATE_RELEASED,
		AppliedAt: row.AppliedAt, ExpiresAt: row.ExpiresAt, ReleasedAt: now, ReleasedBy: threatdetect.ReleasedByOrphanSweep,
		ProcessKilled: row.KilledPID != 0, // the store keeps a kill recorded by another path
	})
	r.auditLog(ctx, "release", fmt.Sprintf("%d", row.ID), fmt.Sprintf("finding=%d container=%s action=%s released_by=%s (pending apply never confirmed)",
		row.FindingID, row.Container, row.Action, threatdetect.ReleasedByOrphanSweep))
	log.Printf("[process-responder] orphaned %s on %s undone (finding %d)", row.Action, row.Container, row.FindingID)
	return nil
}

// Run drives the work queue and the TTL sweep (every
// processActionSweepInterval) until ctx ends.
func (r *ProcessResponder) Run(ctx context.Context) {
	go r.runQueue(ctx)
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
	// async hands the responder's work to its queue instead of running it on
	// the caller's goroutine (production; see NewAsyncActingSink).
	async bool
}

// NewActingSink wraps inner with responder.
func NewActingSink(inner threatdetect.FindingSink, responder *ProcessResponder) *ActingSink {
	return &ActingSink{inner: inner, responder: responder}
}

// NewAsyncActingSink is NewActingSink whose responder work runs on the
// responder's worker (started by ProcessResponder.Run): an upsert from the
// exec ring consumer returns as soon as the finding is stored, and a full
// queue drops the job instead of blocking. The returned finding then does
// not yet carry the response; the worker records it on the stored row.
func NewAsyncActingSink(inner threatdetect.FindingSink, responder *ProcessResponder) *ActingSink {
	return &ActingSink{inner: inner, responder: responder, async: true}
}

// Upsert writes through inner, then lets the responder act. The finding
// returned carries the response the responder recorded, if any.
func (s *ActingSink) Upsert(ctx context.Context, f *threatdetect.Finding) (*threatdetect.Finding, error) {
	out, err := s.inner.Upsert(ctx, f)
	if err != nil || out == nil || s.responder == nil {
		return out, err
	}
	// The kill target is the exec of THIS write (the process that just
	// matched), not whatever the store kept as the newest evidence.
	target := lastExec(f)
	if target == nil {
		target = lastExec(out)
	}
	// Likewise the box is the one this write came from. A finding shared by
	// several boxes of a tenant (#2766) may come back from the store carrying
	// the container that first opened it (the in-memory store does; the
	// Postgres store returns the writer's); the response belongs to this
	// write's box.
	if f.Container != "" && out.Container != f.Container {
		cp := *out
		cp.Container = f.Container
		out = &cp
	}
	if s.async {
		// Only findings the responder can act on take a queue slot, so
		// posture or health findings never crowd out a miner.
		if respondable(out) {
			s.responder.enqueue(out, target)
		}
		return out, nil
	}
	if acted := s.responder.onFinding(ctx, out, target); acted != nil {
		return acted, nil
	}
	return out, nil
}
