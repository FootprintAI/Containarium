package server

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeHealthStore is an in-memory finding store with the same open-dedupe
// contract as FindingStore/MemFindingStore: an Upsert whose (rule, tenant,
// subject) matches an open row bumps that row's count instead of inserting.
type fakeHealthStore struct {
	mu      sync.Mutex
	nextID  int64
	rows    []*threatdetect.Finding
	upserts int
}

func (s *fakeHealthStore) Upsert(_ context.Context, f *threatdetect.Finding) (*threatdetect.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upserts++
	for _, r := range s.rows {
		if r.State == threatdetect.FindingStateOpen && r.Rule == f.Rule && r.TenantID == f.TenantID && r.Subject == f.Subject {
			r.Count++
			return r, nil
		}
	}
	s.nextID++
	cp := *f
	cp.ID = s.nextID
	cp.State = threatdetect.FindingStateOpen
	cp.Count = 1
	s.rows = append(s.rows, &cp)
	return &cp, nil
}

func (s *fakeHealthStore) Get(_ context.Context, id int64) (*threatdetect.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, threatdetect.ErrFindingNotFound
}

func (s *fakeHealthStore) List(_ context.Context, filter threatdetect.ListFilter) ([]*threatdetect.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*threatdetect.Finding
	for _, r := range s.rows {
		if filter.State != "" && r.State != filter.State {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func (s *fakeHealthStore) Resolve(_ context.Context, id int64) (*threatdetect.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.ID == id {
			if r.State != threatdetect.FindingStateOpen {
				return nil, threatdetect.ErrFindingNotOpen
			}
			r.State = threatdetect.FindingStateResolved
			return r, nil
		}
	}
	return nil, threatdetect.ErrFindingNotFound
}

func (s *fakeHealthStore) open() []*threatdetect.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*threatdetect.Finding
	for _, r := range s.rows {
		if r.State == threatdetect.FindingStateOpen {
			out = append(out, r)
		}
	}
	return out
}

func statusResp(state pb.SentryState, reason string) *pb.GetSentryStatusResponse {
	return &pb.GetSentryStatusResponse{State: state, Reason: reason}
}

// TestSentryHealthCheck drives the loop's single-tick Check through a
// sequence of sentry states and asserts the open SENTRY_UNAVAILABLE rows
// after the last one (#2634 acceptance criteria 1 and 2).
func TestSentryHealthCheck(t *testing.T) {
	const (
		noObj   = "eBPF object not loaded (set CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT)"
		failed  = "eBPF network-policy enforcer failed to start: load: permission denied"
		degrade = "FindingStore has no Postgres connection; findings are not persisted across a restart"
	)
	unhealthyRule := &pb.GetSentryStatusResponse{
		State:  pb.SentryState_SENTRY_STATE_OK,
		Reason: "rule DENY_BURST unhealthy: panic: boom",
		Rules:  []*pb.RuleStatus{{Rule: pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST, Healthy: false, LastError: "panic: boom"}},
	}
	tests := []struct {
		name         string
		steps        []*pb.GetSentryStatusResponse
		wantOpen     []string // subjects of open rows, in insertion order
		wantResolved int
		wantCount    int64 // count on the single open row, when wantOpen has one
	}{
		{name: "unavailable raises one medium finding", steps: []*pb.GetSentryStatusResponse{statusResp(pb.SentryState_SENTRY_STATE_UNAVAILABLE, noObj)}, wantOpen: []string{noObj}, wantCount: 1},
		{name: "degraded raises", steps: []*pb.GetSentryStatusResponse{statusResp(pb.SentryState_SENTRY_STATE_DEGRADED, degrade)}, wantOpen: []string{degrade}, wantCount: 1},
		{name: "unhealthy rule raises", steps: []*pb.GetSentryStatusResponse{unhealthyRule}, wantOpen: []string{unhealthyRule.Reason}, wantCount: 1},
		{name: "ok raises nothing", steps: []*pb.GetSentryStatusResponse{statusResp(pb.SentryState_SENTRY_STATE_OK, "")}},
		{name: "disabled raises nothing", steps: []*pb.GetSentryStatusResponse{statusResp(pb.SentryState_SENTRY_STATE_DISABLED, "CONTAINARIUM_THREAT_SENTRY is not set")}},
		{
			name:      "same reason repeated dedupes into one row with a count",
			steps:     []*pb.GetSentryStatusResponse{statusResp(pb.SentryState_SENTRY_STATE_UNAVAILABLE, noObj), statusResp(pb.SentryState_SENTRY_STATE_UNAVAILABLE, noObj), statusResp(pb.SentryState_SENTRY_STATE_UNAVAILABLE, noObj)},
			wantOpen:  []string{noObj},
			wantCount: 3,
		},
		{
			name:         "reason change opens a new subject and resolves the old",
			steps:        []*pb.GetSentryStatusResponse{statusResp(pb.SentryState_SENTRY_STATE_UNAVAILABLE, noObj), statusResp(pb.SentryState_SENTRY_STATE_UNAVAILABLE, failed)},
			wantOpen:     []string{failed},
			wantResolved: 1,
			wantCount:    1,
		},
		{
			name:         "back to ok resolves the open finding",
			steps:        []*pb.GetSentryStatusResponse{statusResp(pb.SentryState_SENTRY_STATE_UNAVAILABLE, noObj), statusResp(pb.SentryState_SENTRY_STATE_OK, "")},
			wantResolved: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeHealthStore{}
			i := 0
			h := NewSentryHealth(func() *pb.GetSentryStatusResponse { return tt.steps[i] }, store, func() string { return "backend-1" }, nil, time.Minute)
			for i = range tt.steps {
				h.Check(context.Background())
			}
			open := store.open()
			if len(open) != len(tt.wantOpen) {
				t.Fatalf("open rows = %d (%+v), want %d", len(open), open, len(tt.wantOpen))
			}
			for j, f := range open {
				if f.Subject != tt.wantOpen[j] {
					t.Errorf("open[%d].Subject = %q, want %q", j, f.Subject, tt.wantOpen[j])
				}
				if f.Rule != pb.ThreatRuleId_THREAT_RULE_ID_SENTRY_UNAVAILABLE || f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM {
					t.Errorf("open[%d] rule/severity = %v/%v, want SENTRY_UNAVAILABLE/MEDIUM", j, f.Rule, f.Severity)
				}
				if f.TenantID != "" || f.Container != "" || f.BackendID != "backend-1" {
					t.Errorf("open[%d] tenant/container/backend = %q/%q/%q, want \"\"/\"\"/backend-1", j, f.TenantID, f.Container, f.BackendID)
				}
				if len(f.Evidence.Configs) != 1 || f.Evidence.Configs[0].Note != f.Subject {
					t.Errorf("open[%d] evidence = %+v, want one ConfigEvidence{Note: reason}", j, f.Evidence)
				}
				if len(open) == 1 && f.Count != tt.wantCount {
					t.Errorf("count = %d, want %d", f.Count, tt.wantCount)
				}
			}
			resolved := 0
			for _, r := range store.rows {
				if r.State == threatdetect.FindingStateResolved {
					resolved++
				}
			}
			if resolved != tt.wantResolved {
				t.Errorf("resolved rows = %d, want %d", resolved, tt.wantResolved)
			}
		})
	}
}

// A restarted daemon must resolve a SENTRY_UNAVAILABLE row an earlier
// process left open once the sentry is healthy — otherwise a persisted
// finding outlives the fault forever. Rows for other backends or rules are
// left alone.
func TestSentryHealthCheck_ResolvesRowLeftOpenByPreviousProcess(t *testing.T) {
	store := &fakeHealthStore{}
	ctx := context.Background()
	stale, _ := store.Upsert(ctx, &threatdetect.Finding{Rule: pb.ThreatRuleId_THREAT_RULE_ID_SENTRY_UNAVAILABLE, BackendID: "backend-1", Subject: "old reason"})
	other, _ := store.Upsert(ctx, &threatdetect.Finding{Rule: pb.ThreatRuleId_THREAT_RULE_ID_SENTRY_UNAVAILABLE, BackendID: "backend-2", Subject: "other backend reason"})
	unrelated, _ := store.Upsert(ctx, &threatdetect.Finding{Rule: pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST, BackendID: "backend-1", TenantID: "t1"})

	h := NewSentryHealth(func() *pb.GetSentryStatusResponse { return statusResp(pb.SentryState_SENTRY_STATE_OK, "") }, store, func() string { return "backend-1" }, nil, time.Minute)
	h.Check(ctx)

	if stale.State != threatdetect.FindingStateResolved {
		t.Errorf("stale own-backend row state = %s, want resolved", stale.State)
	}
	if other.State != threatdetect.FindingStateOpen || unrelated.State != threatdetect.FindingStateOpen {
		t.Errorf("other-backend/unrelated rows = %s/%s, want both open", other.State, unrelated.State)
	}
}

// Run checks immediately at startup (so the finding lands well inside the
// 60 s acceptance window) and then once per tick.
func TestSentryHealthRun_ChecksAtStartupThenEveryTick(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	checked := make(chan struct{}, 10)
	ticks := make(chan time.Time)
	var gotInterval time.Duration
	newTicker := func(d time.Duration) (<-chan time.Time, func()) {
		gotInterval = d
		return ticks, func() {}
	}
	status := func() *pb.GetSentryStatusResponse {
		mu.Lock()
		calls++
		mu.Unlock()
		checked <- struct{}{}
		return statusResp(pb.SentryState_SENTRY_STATE_UNAVAILABLE, "eBPF object not loaded")
	}
	store := &fakeHealthStore{}
	h := NewSentryHealth(status, store, func() string { return "b" }, newTicker, sentryHealthInterval)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { h.Run(ctx); close(done) }()

	waitChecked := func(what string) {
		select {
		case <-checked:
		case <-time.After(2 * time.Second):
			t.Fatalf("no check %s", what)
		}
	}
	waitChecked("at startup")
	ticks <- time.Now()
	waitChecked("after the first tick")
	cancel()
	<-done

	if gotInterval != 60*time.Second {
		t.Errorf("interval = %v, want 60s", gotInterval)
	}
	if calls != 2 {
		t.Errorf("status calls = %d, want 2", calls)
	}
	if open := store.open(); len(open) != 1 || open[0].Count != 2 {
		t.Errorf("open rows = %+v, want one row with count 2", open)
	}
}

// Acceptance criterion 3: a backend without CONTAINARIUM_THREAT_SENTRY never
// builds the loop, so it can never raise anything.
func TestNewSentryHealthIfArmed(t *testing.T) {
	statusCalled := false
	status := func() *pb.GetSentryStatusResponse {
		statusCalled = true
		return statusResp(pb.SentryState_SENTRY_STATE_UNAVAILABLE, "x")
	}
	tests := []struct {
		name    string
		armed   bool
		store   sentryHealthStore
		wantNil bool
	}{
		{name: "unarmed", armed: false, store: &fakeHealthStore{}, wantNil: true},
		{name: "armed without a store", armed: true, store: nil, wantNil: true},
		{name: "armed with a store", armed: true, store: &fakeHealthStore{}, wantNil: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newSentryHealthIfArmed(tt.armed, status, tt.store, func() string { return "" })
			if (h == nil) != tt.wantNil {
				t.Fatalf("newSentryHealthIfArmed = %v, want nil=%v", h, tt.wantNil)
			}
		})
	}
	if statusCalled {
		t.Error("status was called while constructing; the loop must not check before Run")
	}
}

// panicRule panics on every sweep, flipping its health to unhealthy.
type panicRule struct{ id pb.ThreatRuleId }

func (r *panicRule) ID() pb.ThreatRuleId { return r.id }
func (r *panicRule) OnFlows(threatdetect.RuleContext, []netbpf.FlowRecord) []threatdetect.RawFinding {
	return nil
}
func (r *panicRule) OnDeny(threatdetect.RuleContext, netbpf.DenyEvent) []threatdetect.RawFinding {
	return nil
}
func (r *panicRule) Sweep(threatdetect.RuleContext, time.Time) []threatdetect.RawFinding {
	panic(fmt.Sprintf("boom %d", r.id))
}

// The finding's subject is the reason `containarium security sentry status`
// prints, so an unhealthy rule has to put its reason in that field too —
// otherwise the status says OK with an empty reason while a finding is open.
func TestGetSentryStatus_UnhealthyRuleSetsReason(t *testing.T) {
	engine := threatdetect.NewEngine(&fakeFindingSink{}, "backend-1", false, nil, nil)
	engine.Register(&fakeRule{id: pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION})
	engine.Register(&panicRule{id: pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST})
	engine.Sweep(time.Now())
	s := NewThreatDetectionServer(engine, true, true, "")

	resp, err := s.GetSentryStatus(secReadCtx(), &pb.GetSentryStatusRequest{})
	if err != nil {
		t.Fatalf("GetSentryStatus: %v", err)
	}
	if want := "rule DENY_BURST unhealthy: panic: boom 3"; resp.Reason != want {
		t.Errorf("reason = %q, want %q", resp.Reason, want)
	}
	if got := s.sentryStatus(); got.GetReason() != resp.Reason || got.GetState() != resp.State {
		t.Errorf("sentryStatus() = %v/%q, want the RPC's %v/%q", got.GetState(), got.GetReason(), resp.State, resp.Reason)
	}
}
