package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeActuator is the containerActuator test double: an in-memory
// limits.cpu / limits.cpu.allowance pair and a frozen flag per container,
// plus a scripted failure.
type fakeActuator struct {
	mu     sync.Mutex
	count  map[string]string
	allow  map[string]string
	frozen map[string]bool
	fail   error
	calls  []string
}

func newFakeActuator() *fakeActuator {
	return &fakeActuator{count: map[string]string{}, allow: map[string]string{}, frozen: map[string]bool{}}
}

func (a *fakeActuator) CPULimit(name string) (string, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "CPULimit:"+name)
	if a.fail != nil {
		return "", "", a.fail
	}
	return a.count[name], a.allow[name], nil
}

func (a *fakeActuator) SetCPULimit(name, count, allowance string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "SetCPULimit:"+name+":"+count+":"+allowance)
	if a.fail != nil {
		return a.fail
	}
	a.count[name], a.allow[name] = count, allowance
	return nil
}

func (a *fakeActuator) Freeze(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "Freeze:"+name)
	if a.fail != nil {
		return a.fail
	}
	a.frozen[name] = true
	return nil
}

func (a *fakeActuator) Unfreeze(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "Unfreeze:"+name)
	if a.fail != nil {
		return a.fail
	}
	a.frozen[name] = false
	return nil
}

// fakeFindings is an in-memory findingLifecycle: enough of a finding store
// for the responder (Get/Resolve/SetResponse/Upsert) without Postgres or
// the audit chain that MemFindingStore needs.
type fakeFindings struct {
	mu     sync.Mutex
	nextID int64
	rows   map[int64]*threatdetect.Finding
	// writes is every response handed to SetResponse, as written (before
	// the sticky process_killed merge), so a test can tell what a path
	// recorded from what the store kept.
	writes []threatdetect.FindingResponse
}

func newFakeFindings() *fakeFindings { return &fakeFindings{rows: map[int64]*threatdetect.Finding{}} }

func (s *fakeFindings) Upsert(_ context.Context, f *threatdetect.Finding) (*threatdetect.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.State == threatdetect.FindingStateOpen && r.Rule == f.Rule && r.TenantID == f.TenantID && r.Subject == f.Subject {
			r.Count++
			cp := *r // a real store returns a fresh row, never its own
			return &cp, nil
		}
	}
	s.nextID++
	f.ID = s.nextID
	f.State = threatdetect.FindingStateOpen
	f.Count = 1
	s.rows[f.ID] = f
	cp := *f
	return &cp, nil
}

func (s *fakeFindings) Get(_ context.Context, id int64) (*threatdetect.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.rows[id]; ok {
		cp := *f
		return &cp, nil
	}
	return nil, threatdetect.ErrFindingNotFound
}

func (s *fakeFindings) Resolve(_ context.Context, id int64) (*threatdetect.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.rows[id]
	if !ok {
		return nil, threatdetect.ErrFindingNotFound
	}
	if f.State != threatdetect.FindingStateOpen {
		return nil, threatdetect.ErrFindingNotOpen
	}
	f.State = threatdetect.FindingStateResolved
	return f, nil
}

func (s *fakeFindings) SetResponse(_ context.Context, id int64, r threatdetect.FindingResponse) (*threatdetect.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.rows[id]
	if !ok {
		return nil, threatdetect.ErrFindingNotFound
	}
	s.writes = append(s.writes, r)
	resp := r
	// process_killed is sticky, as in both real stores (#2766).
	resp.KeepKillOf(f.Response)
	f.Response = &resp
	cp := *f
	return &cp, nil
}

// lastWrite is the response most recently handed to SetResponse.
func (s *fakeFindings) lastWrite() threatdetect.FindingResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes[len(s.writes)-1]
}

func (s *fakeFindings) byRule(rule pb.ThreatRuleId) []*threatdetect.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*threatdetect.Finding
	for _, f := range s.rows {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

type fakeAudit struct {
	mu      sync.Mutex
	entries []*audit.AuditEntry
}

func (a *fakeAudit) Log(_ context.Context, e *audit.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func (a *fakeAudit) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.entries {
		if e.ResourceType == "security.action" {
			out = append(out, e.Action)
		}
	}
	return out
}

type responderFixture struct {
	r        *ProcessResponder
	act      *fakeActuator
	findings *fakeFindings
	actions  threatdetect.ActionStore
	policies *threatdetect.ProcessPolicyStore
	audit    *fakeAudit
	clock    time.Time
}

func newResponderFixture(t *testing.T, degraded bool) *responderFixture {
	t.Helper()
	fx := &responderFixture{
		act:      newFakeActuator(),
		findings: newFakeFindings(),
		actions:  threatdetect.NewMemActionStore(),
		policies: threatdetect.NewProcessPolicyStore(nil),
		audit:    &fakeAudit{},
		clock:    time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
	}
	fx.r = NewProcessResponder(fx.policies, fx.actions, fx.findings, fx.act, fx.audit, degraded)
	fx.r.now = func() time.Time { return fx.clock }
	return fx
}

func (fx *responderFixture) setDefault(t *testing.T, action pb.ProcessAction, allowance string, ttl time.Duration) {
	t.Helper()
	p := &pb.ProcessPolicy{Action: action, ThrottleAllowance: allowance}
	if ttl != 0 {
		p.Ttl = durationpb.New(ttl)
	}
	if err := fx.policies.SetDefault(context.Background(), p); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
}

// fire upserts a HIGH mining-behavior finding through the ActingSink, the
// way the engine does in production, and returns the stored finding.
func (fx *responderFixture) fire(t *testing.T, container string, rule pb.ThreatRuleId, sev pb.ThreatSeverity) *threatdetect.Finding {
	t.Helper()
	sink := NewActingSink(fx.findings, fx.r)
	out, err := sink.Upsert(context.Background(), &threatdetect.Finding{
		Rule: rule, Severity: sev, TenantID: "tenant-a", Container: container, Subject: "203.0.113.9:3333",
	})
	if err != nil {
		t.Fatalf("Upsert through ActingSink: %v", err)
	}
	return out
}

const (
	ruleMiningBehavior = pb.ThreatRuleId(6) // THREAT_RULE_ID_MINING_BEHAVIOR (#2635)
	ruleMinerSignature = pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE
)

// The responder's action table: what each policy does to the box, what it
// records, and what it leaves alone.
func TestProcessResponder_Apply(t *testing.T) {
	tests := []struct {
		name         string
		policy       pb.ProcessAction
		rule         pb.ThreatRuleId
		severity     pb.ThreatSeverity
		degraded     bool
		wantAction   pb.ProcessAction
		wantState    pb.ResponseState
		wantAllow    string
		wantFrozen   bool
		wantOpenRow  bool
		wantAuditOps []string
	}{
		{
			name: "ALERT does nothing to the box", policy: pb.ProcessAction_PROCESS_ACTION_ALERT,
			rule: ruleMiningBehavior, severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH,
			wantAction: pb.ProcessAction_PROCESS_ACTION_ALERT, wantState: pb.ResponseState_RESPONSE_STATE_NONE,
			wantAllow: "200ms/100ms", wantAuditOps: []string{"alert"},
		},
		{
			name: "THROTTLE records the previous limit and applies the allowance", policy: pb.ProcessAction_PROCESS_ACTION_THROTTLE,
			rule: ruleMiningBehavior, severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH,
			wantAction: pb.ProcessAction_PROCESS_ACTION_THROTTLE, wantState: pb.ResponseState_RESPONSE_STATE_APPLIED,
			wantAllow: "10ms/100ms", wantOpenRow: true, wantAuditOps: []string{"apply"}, // 10% of ONE core as a hard CFS quota, never Incus's soft "N%" share (#2676)
		},
		{
			name: "FREEZE freezes and keeps the limit", policy: pb.ProcessAction_PROCESS_ACTION_FREEZE,
			rule: ruleMinerSignature, severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH,
			wantAction: pb.ProcessAction_PROCESS_ACTION_FREEZE, wantState: pb.ResponseState_RESPONSE_STATE_APPLIED,
			wantAllow: "200ms/100ms", wantFrozen: true, wantOpenRow: true, wantAuditOps: []string{"apply"},
		},
		{
			name: "MEDIUM finding never acts", policy: pb.ProcessAction_PROCESS_ACTION_THROTTLE,
			rule: ruleMiningBehavior, severity: pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM,
			wantAllow: "200ms/100ms",
		},
		{
			name: "a rule outside the mining pair never acts", policy: pb.ProcessAction_PROCESS_ACTION_FREEZE,
			rule: pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION, severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH,
			wantAllow: "200ms/100ms",
		},
		{
			name: "degraded store forces ALERT over a THROTTLE policy", policy: pb.ProcessAction_PROCESS_ACTION_THROTTLE,
			rule: ruleMiningBehavior, severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH, degraded: true,
			wantAction: pb.ProcessAction_PROCESS_ACTION_ALERT, wantState: pb.ResponseState_RESPONSE_STATE_NONE,
			wantAllow: "200ms/100ms", wantAuditOps: []string{"alert"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newResponderFixture(t, tt.degraded)
			fx.act.count["box-a"], fx.act.allow["box-a"] = "2", "200ms/100ms"
			fx.setDefault(t, tt.policy, "", 0)

			f := fx.fire(t, "box-a", tt.rule, tt.severity)

			if got := fx.act.allow["box-a"]; got != tt.wantAllow {
				t.Errorf("allowance after finding = %q, want %q", got, tt.wantAllow)
			}
			if got := fx.act.count["box-a"]; got != "2" {
				t.Errorf("limits.cpu after finding = %q, want the original 2 kept", got)
			}
			if fx.act.frozen["box-a"] != tt.wantFrozen {
				t.Errorf("frozen = %v, want %v", fx.act.frozen["box-a"], tt.wantFrozen)
			}
			if tt.wantAction == pb.ProcessAction_PROCESS_ACTION_UNSPECIFIED {
				if f.Response != nil {
					t.Fatalf("response = %+v, want none", f.Response)
				}
			} else {
				if f.Response == nil {
					t.Fatalf("finding has no response, want %v/%v", tt.wantAction, tt.wantState)
				}
				if f.Response.Action != tt.wantAction || f.Response.State != tt.wantState {
					t.Errorf("response = %v/%v, want %v/%v", f.Response.Action, f.Response.State, tt.wantAction, tt.wantState)
				}
				if !f.Response.AppliedAt.Equal(fx.clock) {
					t.Errorf("applied_at = %v, want %v", f.Response.AppliedAt, fx.clock)
				}
			}
			row, err := fx.actions.Open(context.Background(), "box-a")
			if tt.wantOpenRow {
				if err != nil {
					t.Fatalf("Open action row: %v", err)
				}
				if row.FindingID != f.ID || row.Action != tt.wantAction {
					t.Errorf("action row = %+v, want finding %d %v", row, f.ID, tt.wantAction)
				}
				// Only THROTTLE has a previous limit to restore; FREEZE leaves
				// the limit untouched.
				if tt.wantAction == pb.ProcessAction_PROCESS_ACTION_THROTTLE && (row.PrevCPUCount != "2" || row.PrevCPUAllowance != "200ms/100ms") {
					t.Errorf("action row prev = %q/%q, want 2/200ms/100ms", row.PrevCPUCount, row.PrevCPUAllowance)
				}
				if !row.ExpiresAt.Equal(fx.clock.Add(24 * time.Hour)) {
					t.Errorf("expires_at = %v, want applied+24h", row.ExpiresAt)
				}
				if !f.Response.ExpiresAt.Equal(row.ExpiresAt) {
					t.Errorf("response.expires_at = %v, want %v", f.Response.ExpiresAt, row.ExpiresAt)
				}
			} else if !errors.Is(err, threatdetect.ErrNoOpenAction) {
				t.Errorf("Open action row = %+v, %v; want none", row, err)
			}
			if got := fx.audit.actions(); strings.Join(got, ",") != strings.Join(tt.wantAuditOps, ",") {
				t.Errorf("security.action audit ops = %v, want %v", got, tt.wantAuditOps)
			}
		})
	}
}

// One open action per container: a second HIGH finding — same rule
// re-firing, or the other mining rule — does not act again while the first
// is open.
func TestProcessResponder_DedupesOpenAction(t *testing.T) {
	fx := newResponderFixture(t, false)
	fx.act.count["box-a"], fx.act.allow["box-a"] = "2", "200ms/100ms"
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", 0)

	fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
	fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
	fx.fire(t, "box-a", ruleMinerSignature, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)

	sets := 0
	for _, c := range fx.act.calls {
		if strings.HasPrefix(c, "SetCPULimit:") {
			sets++
		}
	}
	if sets != 1 {
		t.Fatalf("SetCPULimit called %d times, want 1; calls: %v", sets, fx.act.calls)
	}
	if got := fx.audit.actions(); len(got) != 1 {
		t.Fatalf("audit ops = %v, want exactly one apply", got)
	}
}

// release restores exactly what was recorded (count and allowance), marks
// the row released by the operator, and resolves the finding.
func TestProcessResponder_Release(t *testing.T) {
	tests := []struct {
		name   string
		policy pb.ProcessAction
	}{
		{"THROTTLE", pb.ProcessAction_PROCESS_ACTION_THROTTLE},
		{"FREEZE", pb.ProcessAction_PROCESS_ACTION_FREEZE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newResponderFixture(t, false)
			fx.act.count["box-a"], fx.act.allow["box-a"] = "2", "200ms/100ms"
			fx.setDefault(t, tt.policy, "", 0)
			f := fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)

			fx.clock = fx.clock.Add(10 * time.Minute)
			released, _, err := fx.r.Release(context.Background(), "box-a")
			if err != nil {
				t.Fatalf("Release: %v", err)
			}
			if released.ID != f.ID {
				t.Fatalf("Release returned finding %d, want %d", released.ID, f.ID)
			}
			if fx.act.count["box-a"] != "2" || fx.act.allow["box-a"] != "200ms/100ms" || fx.act.frozen["box-a"] {
				t.Errorf("box after release: count=%q allow=%q frozen=%v, want 2/200ms/100ms/false",
					fx.act.count["box-a"], fx.act.allow["box-a"], fx.act.frozen["box-a"])
			}
			if released.State != threatdetect.FindingStateResolved {
				t.Errorf("finding state = %s, want resolved", released.State)
			}
			r := released.Response
			if r == nil || r.State != pb.ResponseState_RESPONSE_STATE_RELEASED || r.ReleasedBy != threatdetect.ReleasedByOperator || !r.ReleasedAt.Equal(fx.clock) {
				t.Errorf("response = %+v, want RELEASED by operator at %v", r, fx.clock)
			}
			if _, err := fx.actions.Open(context.Background(), "box-a"); !errors.Is(err, threatdetect.ErrNoOpenAction) {
				t.Errorf("action still open after release: %v", err)
			}
			if _, _, err := fx.r.Release(context.Background(), "box-a"); !errors.Is(err, threatdetect.ErrNoOpenAction) {
				t.Errorf("second Release = %v, want ErrNoOpenAction", err)
			}
			if got := fx.audit.actions(); strings.Join(got, ",") != "apply,release" {
				t.Errorf("audit ops = %v, want apply,release", got)
			}
		})
	}
}

// The TTL backstop: an action past expires_at is released with no operator,
// the original finding's response says EXPIRED (and stays open), and a
// MEDIUM PROCESS_ACTION_EXPIRED finding is raised so nobody misses it.
func TestProcessResponder_TTLSweep(t *testing.T) {
	fx := newResponderFixture(t, false)
	fx.act.count["box-a"], fx.act.allow["box-a"] = "2", "200ms/100ms"
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", 2*time.Hour)
	f := fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)

	if n := fx.r.SweepExpired(context.Background(), fx.clock.Add(time.Hour)); n != 0 {
		t.Fatalf("SweepExpired before the TTL released %d, want 0", n)
	}
	if fx.act.allow["box-a"] != "10ms/100ms" {
		t.Fatalf("allowance changed before the TTL: %q", fx.act.allow["box-a"])
	}

	fx.clock = fx.clock.Add(2 * time.Hour)
	if n := fx.r.SweepExpired(context.Background(), fx.clock); n != 1 {
		t.Fatalf("SweepExpired at the TTL released %d, want 1", n)
	}
	if fx.act.count["box-a"] != "2" || fx.act.allow["box-a"] != "200ms/100ms" {
		t.Errorf("box after TTL: count=%q allow=%q, want 2/200ms/100ms", fx.act.count["box-a"], fx.act.allow["box-a"])
	}
	got, _ := fx.findings.Get(context.Background(), f.ID)
	if got.State != threatdetect.FindingStateOpen {
		t.Errorf("original finding state = %s, want still open (nobody decided)", got.State)
	}
	if got.Response == nil || got.Response.State != pb.ResponseState_RESPONSE_STATE_EXPIRED || got.Response.ReleasedBy != threatdetect.ReleasedByTTL {
		t.Errorf("original finding response = %+v, want EXPIRED by ttl", got.Response)
	}
	expired := fx.findings.byRule(pb.ThreatRuleId_THREAT_RULE_ID_PROCESS_ACTION_EXPIRED)
	if len(expired) != 1 {
		t.Fatalf("PROCESS_ACTION_EXPIRED findings = %d, want 1", len(expired))
	}
	e := expired[0]
	if e.Severity != pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM || e.Container != "box-a" || e.TenantID != "tenant-a" || e.Subject != "box-a" {
		t.Errorf("expired finding = %+v, want MEDIUM for tenant-a/box-a subject box-a", e)
	}
	if got := fx.audit.actions(); strings.Join(got, ",") != "apply,expire" {
		t.Errorf("audit ops = %v, want apply,expire", got)
	}
	// Released by the TTL: the slot is free, the next HIGH finding acts again.
	fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
	if fx.act.allow["box-a"] != "10ms/100ms" {
		t.Errorf("re-fire after TTL did not throttle again: allowance %q", fx.act.allow["box-a"])
	}
}

// An Incus failure records FAILED with the error on the finding, writes the
// row for the audit trail but leaves no open action (so the rule's next
// sweep is the retry), and never loops.
func TestProcessResponder_ActuatorFailure(t *testing.T) {
	tests := []struct {
		name   string
		policy pb.ProcessAction
	}{
		{"THROTTLE", pb.ProcessAction_PROCESS_ACTION_THROTTLE},
		{"FREEZE", pb.ProcessAction_PROCESS_ACTION_FREEZE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newResponderFixture(t, false)
			fx.act.fail = errors.New("incus: operation timed out")
			fx.setDefault(t, tt.policy, "", 0)

			f := fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)

			if f.Response == nil || f.Response.State != pb.ResponseState_RESPONSE_STATE_FAILED || f.Response.Action != tt.policy {
				t.Fatalf("response = %+v, want %v/FAILED", f.Response, tt.policy)
			}
			if !strings.Contains(f.Response.Error, "operation timed out") {
				t.Errorf("response.error = %q, want the incus error", f.Response.Error)
			}
			if _, err := fx.actions.Open(context.Background(), "box-a"); !errors.Is(err, threatdetect.ErrNoOpenAction) {
				t.Errorf("failed apply left an open action: %v", err)
			}
			if got := fx.audit.actions(); strings.Join(got, ",") != "fail" {
				t.Errorf("audit ops = %v, want fail", got)
			}
			calls := len(fx.act.calls)
			// Once the backoff has passed, the next re-fire is the retry;
			// with Incus healthy again it applies.
			fx.clock = fx.clock.Add(processActionRetryBackoff + time.Second)
			fx.act.fail = nil
			fx.act.count["box-a"], fx.act.allow["box-a"] = "1", ""
			f2 := fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
			if f2.Response == nil || f2.Response.State != pb.ResponseState_RESPONSE_STATE_APPLIED {
				t.Fatalf("re-fire after recovery: response = %+v, want APPLIED", f2.Response)
			}
			if len(fx.act.calls) <= calls {
				t.Errorf("re-fire made no actuator call; calls: %v", fx.act.calls)
			}
		})
	}
}

// A release that Incus refuses keeps the action open (the operator retries)
// and reports the error.
func TestProcessResponder_ReleaseFailureKeepsActionOpen(t *testing.T) {
	fx := newResponderFixture(t, false)
	fx.act.count["box-a"], fx.act.allow["box-a"] = "2", "200ms/100ms"
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_FREEZE, "", 0)
	fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)

	fx.act.fail = errors.New("incus: not frozen")
	if _, _, err := fx.r.Release(context.Background(), "box-a"); err == nil || !strings.Contains(err.Error(), "not frozen") {
		t.Fatalf("Release with a failing actuator = %v, want the incus error", err)
	}
	if _, err := fx.actions.Open(context.Background(), "box-a"); err != nil {
		t.Fatalf("action should still be open after a failed release: %v", err)
	}
	fx.act.fail = nil
	if _, _, err := fx.r.Release(context.Background(), "box-a"); err != nil {
		t.Fatalf("Release retry: %v", err)
	}
}

// Per-container override beats the backend default at apply time.
func TestProcessResponder_UsesContainerOverride(t *testing.T) {
	fx := newResponderFixture(t, false)
	fx.act.count["box-a"], fx.act.allow["box-a"] = "2", "200ms/100ms"
	fx.act.count["box-b"], fx.act.allow["box-b"] = "2", "200ms/100ms"
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", 0)
	if err := fx.policies.SetOverride(context.Background(), "box-b", &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_ALERT}); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}
	fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
	fx.fire(t, "box-b", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
	if fx.act.allow["box-a"] != "10ms/100ms" {
		t.Errorf("box-a (backend default THROTTLE) allowance = %q, want 10ms/100ms (hard quota)", fx.act.allow["box-a"])
	}
	if fx.act.allow["box-b"] != "200ms/100ms" {
		t.Errorf("box-b (override ALERT) allowance = %q, want untouched", fx.act.allow["box-b"])
	}
}

// staleListStore lists a fixed (stale) row as expired, whatever the store
// holds now: the window between SweepExpired's list and its lock.
type staleListStore struct {
	threatdetect.ActionStore
	stale *threatdetect.SecurityAction
}

func (s staleListStore) ListExpired(context.Context, time.Time) ([]*threatdetect.SecurityAction, error) {
	cp := *s.stale
	return []*threatdetect.SecurityAction{&cp}, nil
}

// The sweep listed row A as expired, but by the time it holds the lock the
// container's open action is a newer row B (A was released, then a fresh
// throttle applied): the sweep must touch neither the box nor B.
func TestProcessResponder_SweepSkipsRowSupersededSinceList(t *testing.T) {
	fx := newResponderFixture(t, false)
	ctx := context.Background()
	rowA := &threatdetect.SecurityAction{FindingID: 1, Container: "box-a", TenantID: "tenant-a",
		Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, PrevCPUCount: "1", AppliedAt: fx.clock.Add(-48 * time.Hour), ExpiresAt: fx.clock.Add(-24 * time.Hour)}
	if err := fx.actions.Insert(ctx, rowA); err != nil {
		t.Fatal(err)
	}
	stale := *rowA
	if err := fx.actions.Release(ctx, rowA.ID, threatdetect.ReleasedByOperator, fx.clock.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	rowB := &threatdetect.SecurityAction{FindingID: 2, Container: "box-a", TenantID: "tenant-a",
		Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, PrevCPUCount: "4", AppliedAt: fx.clock, ExpiresAt: fx.clock.Add(-time.Second)}
	if err := fx.actions.Insert(ctx, rowB); err != nil {
		t.Fatal(err)
	}
	fx.r.actions = staleListStore{ActionStore: fx.actions, stale: &stale}

	if n := fx.r.SweepExpired(ctx, fx.clock); n != 0 {
		t.Errorf("SweepExpired released %d, want 0", n)
	}
	if len(fx.act.calls) != 0 {
		t.Errorf("actuator called for a stale row: %v", fx.act.calls)
	}
	got, err := fx.actions.Open(ctx, "box-a")
	if err != nil || got.ID != rowB.ID || got.PrevCPUCount != "4" {
		t.Errorf("row B disturbed: %+v, %v", got, err)
	}
	if len(fx.findings.byRule(pb.ThreatRuleId_THREAT_RULE_ID_PROCESS_ACTION_EXPIRED)) != 0 {
		t.Error("raised an EXPIRED finding for a stale row")
	}
}

// A crash after the row is written but before the box is confirmed leaves
// a PENDING row; the sweep undoes it after PendingOrphanAfter and marks it
// released_by=orphan-sweep.
func TestProcessResponder_SweepReleasesOrphanedPendingRow(t *testing.T) {
	fx := newResponderFixture(t, false)
	ctx := context.Background()
	fx.act.count["box-a"], fx.act.allow["box-a"] = "10%", "" // the throttle took effect before the crash
	row := &threatdetect.SecurityAction{FindingID: 1, Container: "box-a", TenantID: "tenant-a", Pending: true,
		Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, PrevCPUCount: "2", PrevCPUAllowance: "200ms/100ms",
		AppliedAt: fx.clock, ExpiresAt: fx.clock.Add(24 * time.Hour)}
	if err := fx.actions.Insert(ctx, row); err != nil {
		t.Fatal(err)
	}

	if n := fx.r.SweepExpired(ctx, fx.clock.Add(threatdetect.PendingOrphanAfter-time.Second)); n != 0 {
		t.Fatalf("young pending row swept: %d", n)
	}
	if n := fx.r.SweepExpired(ctx, fx.clock.Add(threatdetect.PendingOrphanAfter+time.Second)); n != 1 {
		t.Fatalf("orphan not released: %d", n)
	}
	if fx.act.count["box-a"] != "2" || fx.act.allow["box-a"] != "200ms/100ms" {
		t.Errorf("limits = %q/%q, want the recorded 2/200ms/100ms", fx.act.count["box-a"], fx.act.allow["box-a"])
	}
	last, err := fx.actions.Latest(ctx, "box-a")
	if err != nil || last.ReleasedBy != threatdetect.ReleasedByOrphanSweep {
		t.Errorf("row = %+v, %v, want released_by=orphan-sweep", last, err)
	}
}

// panicActuator dies in SetCPULimit, after the row was inserted.
type panicActuator struct{ *fakeActuator }

func (panicActuator) SetCPULimit(string, string, string) error { panic("daemon died mid-apply") }

// The row is written before the box is touched: an apply that dies leaves
// a PENDING row, which the sweep later releases.
func TestProcessResponder_RowExistsBeforeApplyAndIsSweptAfterCrash(t *testing.T) {
	fx := newResponderFixture(t, false)
	fx.act.count["box-a"], fx.act.allow["box-a"] = "2", ""
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", 0)
	fx.r.act = panicActuator{fx.act}

	func() {
		defer func() { _ = recover() }()
		fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
	}()
	row, err := fx.actions.Open(context.Background(), "box-a")
	if err != nil || !row.Pending || row.PrevCPUCount != "2" {
		t.Fatalf("after the crash: row = %+v, %v, want an open PENDING row recording the previous limit", row, err)
	}
	fx.r.act = fx.act
	if n := fx.r.SweepExpired(context.Background(), fx.clock.Add(threatdetect.PendingOrphanAfter+time.Second)); n != 1 {
		t.Fatalf("sweep released %d, want 1", n)
	}
}

// A FAILED apply is not retried on every re-fire inside the backoff: three
// HIGH re-fires make one actuator attempt and write one row.
func TestProcessResponder_FailedApplyNotRetriedWithinBackoff(t *testing.T) {
	fx := newResponderFixture(t, false)
	fx.act.fail = errors.New("incus: operation timed out")
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_FREEZE, "", 0)

	for i := 0; i < 3; i++ {
		fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
		fx.clock = fx.clock.Add(2 * time.Minute)
	}
	if len(fx.act.calls) != 1 {
		t.Errorf("actuator calls = %v, want exactly 1", fx.act.calls)
	}
	if last, err := fx.actions.Latest(context.Background(), "box-a"); err != nil || last.ID != 1 {
		t.Errorf("latest row = %+v, %v, want the single row (id 1)", last, err)
	}
}
