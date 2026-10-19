package threatdetect

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// RuleContext is what a Rule needs to evaluate flows/deny events, without
// talking to Incus or the DB directly — this is what keeps rules pure and
// table-testable, and lets the engine recover a panicking rule without
// touching shared state.
type RuleContext struct {
	// TenantForIP resolves a container IP to its owning tenant id, backed by
	// the network-policy enforcer's ip_tenant cache (refreshed every 10s
	// reconcile — see NetworkPolicyEnforcer.TenantForIP). ok is false for an
	// unrecognized IP; a rule must never guess at an unknown IP's tenant.
	TenantForIP func(ip netip.Addr) (tenantID string, ok bool)
	// Now is injected so time-window rules (deny-burst) are testable with a
	// fake clock instead of wall time.
	Now func() time.Time
	// MiningThresholds returns the operator-tuned mining-behavior thresholds
	// (#2635), read from the daemon config store by the caller. nil means
	// DefaultMiningThresholds.
	MiningThresholds func() MiningThresholds
}

// CPUSample is one container's CPU usage over one metrics-collector tick
// (#2635), derived from the collector's cumulative CPUUsageSeconds. IP is
// the container's address, which joins the sample to the flow records whose
// source it is.
type CPUSample struct {
	Container string
	IP        netip.Addr
	// Cores is the mean number of busy cores over the tick (1.0 = one core).
	Cores float64
	// LimitCores is the box's limits.cpu in cores; 0 when unlimited.
	LimitCores float64
	At         time.Time
}

// CPUConsumer is an optional interface a Rule implements to receive CPU
// samples. The engine type-asserts on Register, so rules that do not need
// CPU stay unchanged.
type CPUConsumer interface {
	OnCPU(ctx RuleContext, samples []CPUSample) []RawFinding
}

// ExecEvent is one process exec inside a tenant container, as the host-side
// exec telemetry (#2637) delivers it: the kernel record decoded and
// attributed to its container by the server's ExecWatcher. PID and PPID are
// host-namespace ids. Argv is joined with single spaces, capped at 512 bytes
// by the kernel program and never containing the environment. SHA256 is
// empty on the first delivery; a rule that needs it asks the watcher to hash
// /proc/<pid>/exe and gets a second OnExec with it filled (#2638).
type ExecEvent struct {
	Container     string
	TenantID      string
	At            time.Time
	PID           uint32
	PPID          uint32
	UID           uint32
	Comm          string
	Filename      string
	Argv          string
	ArgvTruncated bool
	SHA256        string
}

// ExecConsumer is an optional interface a Rule implements to receive exec
// events (#2637), the exec twin of CPUConsumer: type-asserted on Register,
// fanned out by OnExec with the same per-rule panic recovery.
type ExecConsumer interface {
	OnExec(ctx RuleContext, ev ExecEvent) []RawFinding
}

// RawFinding is what a Rule returns when it fires: enough to build a
// Finding, without the store/lifecycle fields (id, state, count, first/last
// seen) that belong to the engine and the store.
type RawFinding struct {
	Rule      pb.ThreatRuleId
	Severity  pb.ThreatSeverity
	TenantID  string
	Container string
	// Subject is the dedupe scope within (Rule, TenantID) — see the
	// security_findings_open_dedupe index.
	Subject  string
	Evidence Evidence
}

// Rule is one detection rule. Implementations must be pure — no Incus calls,
// no DB access, RuleContext supplies everything needed — which is what keeps
// them table-testable and lets a panicking rule be recovered without
// corrupting shared state.
type Rule interface {
	ID() pb.ThreatRuleId
	OnFlows(ctx RuleContext, flows []netbpf.FlowRecord) []RawFinding
	OnDeny(ctx RuleContext, ev netbpf.DenyEvent) []RawFinding
	// Sweep drives time-window rules (deny-burst) that fire on elapsed time
	// rather than a new signal. Rules with no window state return nil.
	Sweep(ctx RuleContext, now time.Time) []RawFinding
}

// FindingSink is what the engine needs from a finding store: an upsert that
// dedupes an open (rule, tenant, subject) into one row instead of creating a
// duplicate or re-alerting on every repeat. *FindingStore (Postgres) and
// *MemFindingStore (degraded, no Postgres) both satisfy it.
type FindingSink interface {
	Upsert(ctx context.Context, f *Finding) (*Finding, error)
}

// FindingReader is what ThreatDetectionServer's ListFindings/ResolveFinding
// (#1643) need from a finding store — read/lifecycle operations, distinct
// from FindingSink's write path so the two stores' Get/List/Resolve
// implementations (identical contract, Postgres vs. bounded in-memory ring)
// both satisfy it without the engine's hot-path callers depending on it.
type FindingReader interface {
	Get(ctx context.Context, id int64) (*Finding, error)
	List(ctx context.Context, filter ListFilter) ([]*Finding, error)
	Resolve(ctx context.Context, id int64) (*Finding, error)
}

// ruleHealth tracks one rule's panic-recovery state for GetSentryStatus. A
// rule starts healthy; a recovered panic flips it unhealthy until the
// process restarts (there's no auto-recovery — an operator should notice and
// fix the rule, not have the dashboard quietly go green again).
type ruleHealth struct {
	healthy     bool
	lastError   string
	lastErrorAt time.Time
}

// RuleStatusInfo mirrors pb.RuleStatus as a plain Go struct so the engine
// stays independent of the wire type; the gRPC server converts.
type RuleStatusInfo struct {
	Rule        pb.ThreatRuleId
	Healthy     bool
	LastError   string
	LastErrorAt time.Time
}

// Engine fans eBPF flow/deny signals out to registered rules and upserts
// their findings into the sink. See
// docs/architecture/continuous-threat-detection.md. Requires the eBPF object
// loaded (wired via the enforcer's SetFlowHook/SetDenyHook) but NOT
// CONTAINARIUM_NETWORK_POLICY_ENFORCE — it works in observation mode.
type Engine struct {
	sink      FindingSink
	backendID string
	degraded  bool // true when sink has no Postgres-backed persistence

	ruleCtx RuleContext

	mu        sync.Mutex
	rules     []Rule
	cpuRules  []CPUConsumer
	execRules []ExecConsumer
	health    map[pb.ThreatRuleId]*ruleHealth
}

// NewEngine builds a detection engine over sink. backendID is stamped onto
// every finding this engine writes. degraded marks the sink as
// non-persistent (no Postgres), surfaced via Status(). tenantForIP resolves
// a flow endpoint's IP to its owning tenant; nil disables resolution (every
// rule sees !ok). now defaults to time.Now.
func NewEngine(sink FindingSink, backendID string, degraded bool, tenantForIP func(netip.Addr) (string, bool), now func() time.Time) *Engine {
	if now == nil {
		now = time.Now
	}
	if tenantForIP == nil {
		tenantForIP = func(netip.Addr) (string, bool) { return "", false }
	}
	return &Engine{
		sink:      sink,
		backendID: backendID,
		degraded:  degraded,
		ruleCtx:   RuleContext{TenantForIP: tenantForIP, Now: now},
		health:    make(map[pb.ThreatRuleId]*ruleHealth),
	}
}

// SetBackendID updates the backend id stamped onto every finding this
// engine writes from here on. The daemon's local backend id isn't known at
// construction time (it's resolved once the peer pool starts in Start()),
// so this is called after the fact — same lifecycle SecurityServer.SetPeerPool
// and friends follow for the same reason.
func (e *Engine) SetBackendID(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.backendID = id
}

// Register adds a rule to the registry. Not safe to call concurrently with
// OnFlows/OnDeny/Sweep — register every rule before wiring the engine's
// hooks onto the enforcer and starting the sweep ticker.
func (e *Engine) Register(r Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
	if c, ok := r.(CPUConsumer); ok {
		e.cpuRules = append(e.cpuRules, c)
	}
	if c, ok := r.(ExecConsumer); ok {
		e.execRules = append(e.execRules, c)
	}
	e.health[r.ID()] = &ruleHealth{healthy: true}
}

// SetMiningThresholds wires the source of the mining-behavior thresholds
// into every rule's RuleContext. Like Register, call it before wiring hooks.
func (e *Engine) SetMiningThresholds(fn func() MiningThresholds) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ruleCtx.MiningThresholds = fn
}

// OnCPU is the metrics collector's CPU hook (via the server's CPUSampler):
// fan the samples out to every rule implementing CPUConsumer, with the same
// panic recovery as the flow and deny paths.
func (e *Engine) OnCPU(samples []CPUSample) {
	e.mu.Lock()
	rules := append([]CPUConsumer(nil), e.cpuRules...)
	e.mu.Unlock()
	for _, r := range rules {
		e.upsertAll(e.evalCPU(r, samples))
	}
}

func (e *Engine) evalCPU(r CPUConsumer, samples []CPUSample) (out []RawFinding) {
	id := pb.ThreatRuleId_THREAT_RULE_ID_UNSPECIFIED
	if rule, ok := r.(Rule); ok {
		id = rule.ID()
	}
	defer e.recoverRule(id)
	return r.OnCPU(e.ruleCtx, samples)
}

// OnExec is the ExecWatcher's hook (#2637): fan one attributed exec event
// out to every rule implementing ExecConsumer, with the same panic recovery
// as the other paths. Runs synchronously on the ring consumer goroutine, so
// a rule must stay cheap here (name/argv matching); anything slower belongs
// off this path.
func (e *Engine) OnExec(ev ExecEvent) {
	e.mu.Lock()
	rules := append([]ExecConsumer(nil), e.execRules...)
	e.mu.Unlock()
	for _, r := range rules {
		e.upsertAll(e.evalExec(r, ev))
	}
}

func (e *Engine) evalExec(r ExecConsumer, ev ExecEvent) (out []RawFinding) {
	id := pb.ThreatRuleId_THREAT_RULE_ID_UNSPECIFIED
	if rule, ok := r.(Rule); ok {
		id = rule.ID()
	}
	defer e.recoverRule(id)
	return r.OnExec(e.ruleCtx, ev)
}

// OnFlows is the enforcer's flow-poll hook (SetFlowHook): fan the batch out
// to every registered rule and upsert whatever findings come back. A
// panicking rule is recovered and marked unhealthy; the rest of the batch
// and every other rule are unaffected. Runs synchronously inside the
// enforcer's 15s flow-poll tick, so worst-case detection latency is one poll
// interval — well inside the 60s budget.
func (e *Engine) OnFlows(flows []netbpf.FlowRecord) {
	for _, r := range e.snapshotRules() {
		e.upsertAll(e.evalFlows(r, flows))
	}
}

// OnDeny is the enforcer's deny-event hook (SetDenyHook).
func (e *Engine) OnDeny(ev netbpf.DenyEvent) {
	for _, r := range e.snapshotRules() {
		e.upsertAll(e.evalDeny(r, ev))
	}
}

// Sweep drives every registered rule's time-window logic. Call on a fixed
// tick (design doc: 30s) — independent of flow/deny traffic, so a
// window-only rule (deny-burst) still resolves even during a quiet period.
func (e *Engine) Sweep(now time.Time) {
	for _, r := range e.snapshotRules() {
		e.upsertAll(e.evalSweep(r, now))
	}
}

func (e *Engine) snapshotRules() []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Rule(nil), e.rules...)
}

func (e *Engine) getBackendID() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.backendID
}

func (e *Engine) evalFlows(r Rule, flows []netbpf.FlowRecord) (out []RawFinding) {
	defer e.recoverRule(r.ID())
	return r.OnFlows(e.ruleCtx, flows)
}

func (e *Engine) evalDeny(r Rule, ev netbpf.DenyEvent) (out []RawFinding) {
	defer e.recoverRule(r.ID())
	return r.OnDeny(e.ruleCtx, ev)
}

func (e *Engine) evalSweep(r Rule, now time.Time) (out []RawFinding) {
	defer e.recoverRule(r.ID())
	return r.Sweep(e.ruleCtx, now)
}

// recoverRule is deferred around every rule call: a panic is contained to
// that one rule (marked unhealthy, visible via Status) rather than taking
// down the engine or the enforcer goroutine it's hooked into.
func (e *Engine) recoverRule(id pb.ThreatRuleId) {
	if p := recover(); p != nil {
		e.markUnhealthy(id, fmt.Errorf("panic: %v", p))
	}
}

func (e *Engine) markUnhealthy(id pb.ThreatRuleId, err error) {
	log.Printf("[threatdetect] rule %s recovered from error: %v", id, err)
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.health[id]
	if h == nil {
		h = &ruleHealth{}
		e.health[id] = h
	}
	h.healthy = false
	h.lastError = err.Error()
	h.lastErrorAt = e.ruleCtx.Now()
}

// upsertAll writes every RawFinding a rule returned to the sink. Deliberately
// outside the recover()-guarded eval* methods: a sink failure (e.g. a dead
// DB) is the store's problem, not the rule's, so it surfaces as a log line
// rather than flipping the rule's health.
func (e *Engine) upsertAll(findings []RawFinding) {
	if len(findings) == 0 {
		return
	}
	ctx := context.Background()
	backendID := e.getBackendID()
	for _, rf := range findings {
		f := &Finding{
			Rule:      rf.Rule,
			Severity:  rf.Severity,
			TenantID:  rf.TenantID,
			Container: rf.Container,
			BackendID: backendID,
			Subject:   rf.Subject,
			Evidence:  rf.Evidence,
		}
		if _, err := e.sink.Upsert(ctx, f); err != nil {
			log.Printf("[threatdetect] upsert finding (rule=%s tenant=%s subject=%s): %v", rf.Rule, rf.TenantID, rf.Subject, err)
		}
	}
}

// Status reports the engine's degraded state and every registered rule's
// health, for GetSentryStatus.
func (e *Engine) Status() (degraded bool, rules []RuleStatusInfo) {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]RuleStatusInfo, 0, len(e.rules))
	for _, r := range e.rules {
		info := RuleStatusInfo{Rule: r.ID(), Healthy: true}
		if h := e.health[r.ID()]; h != nil {
			info.Healthy = h.healthy
			info.LastError = h.lastError
			info.LastErrorAt = h.lastErrorAt
		}
		out = append(out, info)
	}
	return e.degraded, out
}
