package retention

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeSource records the cutoff and held orgs it was asked about and answers
// with a fixed count. It has no way to delete: Source is count-only.
type fakeSource struct {
	class     pb.RetentionClass
	store     string
	count     Count
	err       error
	gotCutoff time.Time
	gotHeld   []string
}

func (f *fakeSource) Class() pb.RetentionClass { return f.class }
func (f *fakeSource) Store() string            { return f.store }
func (f *fakeSource) Count(_ context.Context, cutoff time.Time, held []string) (Count, error) {
	f.gotCutoff, f.gotHeld = cutoff, held
	return f.count, f.err
}

func fixedNow() time.Time { return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC) }

func newTestSweeper(t *testing.T, store Store, srcs []Source, unswept []Unswept) *Sweeper {
	t.Helper()
	s := NewSweeper(store, srcs, unswept)
	s.now = fixedNow
	return s
}

func findStore(t *testing.T, r *pb.RetentionReport, class pb.RetentionClass, store string) *pb.RetentionStoreReport {
	t.Helper()
	for _, s := range r.GetStores() {
		if s.GetClass() == class && s.GetStore() == store {
			return s
		}
	}
	t.Fatalf("report has no %v/%s: %v", class, store, r.GetStores())
	return nil
}

func TestSweeper_CutoffIsNowMinusTheClassWindow(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore()
	if _, err := st.SetPolicy(ctx, []*pb.RetentionWindow{{Class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, Days: 7}}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	prompts := &fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 4, Eligible: 4}}
	logs := &fakeSource{class: pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS, store: "traffic_connections", count: Count{Older: 1, Eligible: 1}}

	rep, err := newTestSweeper(t, st, []Source{prompts, logs}, nil).Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if want := fixedNow().AddDate(0, 0, -7); !prompts.gotCutoff.Equal(want) {
		t.Errorf("prompts cutoff = %v, want %v (the set 7-day window)", prompts.gotCutoff, want)
	}
	if want := fixedNow().AddDate(0, 0, -90); !logs.gotCutoff.Equal(want) {
		t.Errorf("gateway-logs cutoff = %v, want %v (the 90-day default)", logs.gotCutoff, want)
	}
	got := findStore(t, rep, pb.RetentionClass_RETENTION_CLASS_PROMPTS, "agent_tasks")
	if got.GetStatus() != pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_COUNTED || got.GetWindowDays() != 7 ||
		got.GetOlderThanCutoff() != 4 || got.GetEligible() != 4 || got.GetHeld() != 0 {
		t.Errorf("prompts report = %v", got)
	}
	if rep.GetMode() != pb.RetentionMode_RETENTION_MODE_DRY_RUN {
		t.Errorf("mode = %v, want DRY_RUN", rep.GetMode())
	}
	if rep.GetPolicyRevision() != 1 {
		t.Errorf("policy revision = %d, want 1", rep.GetPolicyRevision())
	}
}

func TestSweeper_HeldOrgsArePassedAndNotEligible(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore()
	for _, org := range []string{"org-b", "org-a"} {
		if _, err := st.SetHold(ctx, org, "case", "admin", nil); err != nil {
			t.Fatal(err)
		}
	}
	src := &fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 5, Eligible: 2}}
	rep, err := newTestSweeper(t, st, []Source{src}, nil).Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if strings.Join(src.gotHeld, ",") != "org-a,org-b" {
		t.Errorf("source was given held orgs %v, want [org-a org-b]", src.gotHeld)
	}
	got := findStore(t, rep, pb.RetentionClass_RETENTION_CLASS_PROMPTS, "agent_tasks")
	if got.GetOlderThanCutoff() != 5 || got.GetEligible() != 2 || got.GetHeld() != 3 {
		t.Errorf("older/eligible/held = %d/%d/%d, want 5/2/3", got.GetOlderThanCutoff(), got.GetEligible(), got.GetHeld())
	}
	if rep.GetActiveHolds() != 2 {
		t.Errorf("active holds = %d, want 2", rep.GetActiveHolds())
	}
}

func TestUnattributed_OrglessRowsAreHeldWhileAnyHoldIsActive(t *testing.T) {
	if got := Unattributed(6, nil); got != (Count{Older: 6, Eligible: 6}) {
		t.Errorf("no hold: %+v, want all 6 eligible", got)
	}
	if got := Unattributed(6, []string{"org-a"}); got != (Count{Older: 6, Eligible: 0}) {
		t.Errorf("one hold: %+v, want 6 older and none eligible (Q21 on #2727)", got)
	}
}

func TestSweeper_NotSweptStoresAreListedWithTheirNote(t *testing.T) {
	ctx := context.Background()
	un := []Unswept{{Class: pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS, Store: "audit_logs", Note: "hash-chained; slice D (#2878)"}}
	rep, err := newTestSweeper(t, NewMemoryStore(), nil, un).Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	got := findStore(t, rep, pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS, "audit_logs")
	if got.GetStatus() != pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_NOT_SWEPT || !strings.Contains(got.GetNote(), "#2878") ||
		got.GetCutoff() != nil || got.GetEligible() != 0 {
		t.Errorf("not-swept entry = %v", got)
	}
}

func TestSweeper_ACountFailureIsReportedAndDoesNotStopTheRest(t *testing.T) {
	ctx := context.Background()
	bad := &fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", err: errors.New("connection refused")}
	good := &fakeSource{class: pb.RetentionClass_RETENTION_CLASS_RESPONSES, store: "agent_task_results", count: Count{Older: 2, Eligible: 2}}
	rep, err := newTestSweeper(t, NewMemoryStore(), []Source{bad, good}, nil).Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	b := findStore(t, rep, pb.RetentionClass_RETENTION_CLASS_PROMPTS, "agent_tasks")
	if b.GetStatus() != pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_ERROR || !strings.Contains(b.GetNote(), "connection refused") {
		t.Errorf("failed store = %v", b)
	}
	g := findStore(t, rep, pb.RetentionClass_RETENTION_CLASS_RESPONSES, "agent_task_results")
	if g.GetStatus() != pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_COUNTED || g.GetEligible() != 2 {
		t.Errorf("good store = %v", g)
	}
}

func TestSweeper_StoresAreOrderedByClassThenStore(t *testing.T) {
	srcs := []Source{
		&fakeSource{class: pb.RetentionClass_RETENTION_CLASS_RESPONSES, store: "crew_runs"},
		&fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "crew_runs"},
		&fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks"},
	}
	rep, err := newTestSweeper(t, NewMemoryStore(), srcs, nil).Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range rep.GetStores() {
		got = append(got, s.GetClass().String()+"/"+s.GetStore())
	}
	want := "RETENTION_CLASS_PROMPTS/agent_tasks RETENTION_CLASS_PROMPTS/crew_runs RETENTION_CLASS_RESPONSES/crew_runs"
	if strings.Join(got, " ") != want {
		t.Errorf("order = %v", got)
	}
}

func TestReporter_KeepsTheLastReportAndRefreshes(t *testing.T) {
	ctx := context.Background()
	src := &fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 1, Eligible: 1}}
	r := NewReporter(newTestSweeper(t, NewMemoryStore(), []Source{src}, nil))

	first, err := r.Report(ctx, false)
	if err != nil {
		t.Fatalf("first Report (no sweep yet, so it sweeps inline): %v", err)
	}
	src.count = Count{Older: 9, Eligible: 9}
	again, err := r.Report(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if again.GetStores()[0].GetOlderThanCutoff() != first.GetStores()[0].GetOlderThanCutoff() {
		t.Error("Report(refresh=false) swept again instead of returning the kept report")
	}
	fresh, err := r.Report(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.GetStores()[0].GetOlderThanCutoff() != 9 {
		t.Errorf("Report(refresh=true) = %d, want a new sweep's 9", fresh.GetStores()[0].GetOlderThanCutoff())
	}
}

func TestReporter_RunSweepsAtStartAndStopsWithItsContext(t *testing.T) {
	src := &fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks"}
	r := NewReporter(newTestSweeper(t, NewMemoryStore(), []Source{src}, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx, time.Hour); close(done) }()
	deadline := time.After(5 * time.Second)
	for r.Last() == nil {
		select {
		case <-deadline:
			t.Fatal("no report kept after the start-up sweep")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}
