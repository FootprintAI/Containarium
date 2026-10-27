package retention

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// removerSource is a fakeSource that can also delete. It records every Remove.
type removerSource struct {
	fakeSource
	removed   int64
	skipped   string
	removeErr error
	calls     []removeCall
	log       *[]string // shared event log, to assert ordering
}

type removeCall struct {
	cutoff  time.Time
	held    []string
	maxRows int
}

func (r *removerSource) Remove(_ context.Context, cutoff time.Time, held []string, maxRows int) (Removal, error) {
	r.calls = append(r.calls, removeCall{cutoff, held, maxRows})
	if r.log != nil {
		*r.log = append(*r.log, "remove:"+r.store)
	}
	return Removal{Removed: r.removed, Skipped: r.skipped}, r.removeErr
}

// auditedSweeper is a sweeper with an auditor that accepts every entry, the
// shape of a daemon with an audit store.
func auditedSweeper(t *testing.T, store Store, srcs []Source, unswept []Unswept) *Sweeper {
	t.Helper()
	sw := newTestSweeper(t, store, srcs, unswept)
	sw.SetAuditor(func(context.Context, *pb.RetentionReport) error { return nil })
	return sw
}

func enforcing(t *testing.T) *MemoryStore {
	t.Helper()
	st := NewMemoryStore()
	if _, err := st.SetMode(context.Background(), pb.RetentionMode_RETENTION_MODE_ENFORCE, "admin", nil); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestSweeper_DryRunIsTheDefaultAndNeverRemoves(t *testing.T) {
	src := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 3, Eligible: 3}}, removed: 3}
	rep, err := newTestSweeper(t, NewMemoryStore(), []Source{src}, nil).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(src.calls) != 0 {
		t.Fatalf("Remove was called %d times in DRY_RUN, want never", len(src.calls))
	}
	if rep.GetMode() != pb.RetentionMode_RETENTION_MODE_DRY_RUN || rep.GetEnforced() {
		t.Errorf("report mode/enforced = %v/%v, want DRY_RUN/false", rep.GetMode(), rep.GetEnforced())
	}
	if got := findStore(t, rep, src.class, "agent_tasks"); got.GetRemoved() != 0 || got.GetEligible() != 3 {
		t.Errorf("entry = %v, want 3 eligible and none removed", got)
	}
}

func TestSweeper_EnforceRemovesWhatTheCountSaidAndReportsIt(t *testing.T) {
	src := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 5, Eligible: 4}}, removed: 4}
	st := enforcing(t)
	if _, err := st.SetHold(context.Background(), "org-a", "case", "admin", nil); err != nil {
		t.Fatal(err)
	}
	rep, err := auditedSweeper(t, st, []Source{src}, nil).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(src.calls) != 1 {
		t.Fatalf("Remove called %d times, want once", len(src.calls))
	}
	c := src.calls[0]
	if want := fixedNow().AddDate(0, 0, -30); !c.cutoff.Equal(want) {
		t.Errorf("Remove cutoff = %v, want %v (the 30-day default)", c.cutoff, want)
	}
	if strings.Join(c.held, ",") != "org-a" {
		t.Errorf("Remove was given held orgs %v, want [org-a]", c.held)
	}
	if c.maxRows != MaxRemovePerStore {
		t.Errorf("Remove maxRows = %d, want the bound %d", c.maxRows, MaxRemovePerStore)
	}
	if rep.GetMode() != pb.RetentionMode_RETENTION_MODE_ENFORCE || !rep.GetEnforced() {
		t.Errorf("report mode/enforced = %v/%v, want ENFORCE/true", rep.GetMode(), rep.GetEnforced())
	}
	if got := findStore(t, rep, src.class, "agent_tasks"); got.GetRemoved() != 4 || got.GetEligible() != 4 || got.GetHeld() != 1 {
		t.Errorf("entry = %v, want 4 removed of 4 eligible, 1 held", got)
	}
}

func TestSweeper_APreviewNeverRemovesEvenInEnforceMode(t *testing.T) {
	src := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 2, Eligible: 2}}, removed: 2}
	audited := 0
	sw := newTestSweeper(t, enforcing(t), []Source{src}, nil)
	sw.SetAuditor(func(context.Context, *pb.RetentionReport) error { audited++; return nil })

	rep, err := sw.Preview(context.Background())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if len(src.calls) != 0 || audited != 0 {
		t.Errorf("Preview removed %d times and audited %d times, want neither", len(src.calls), audited)
	}
	if rep.GetMode() != pb.RetentionMode_RETENTION_MODE_ENFORCE || rep.GetEnforced() {
		t.Errorf("preview mode/enforced = %v/%v, want ENFORCE/false", rep.GetMode(), rep.GetEnforced())
	}
}

func TestSweeper_AStoreSharedByTwoClassesIsRemovedOnceByTheLongerWindow(t *testing.T) {
	// A crew run keeps a prompt and a response in one row. With a 30-day
	// prompt window and a 90-day response window, a row is removed only once
	// past 90 days, so neither class loses data early (default proposed on #2877).
	ctx := context.Background()
	st := enforcing(t)
	if _, err := st.SetPolicy(ctx, []*pb.RetentionWindow{
		{Class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, Days: 30},
		{Class: pb.RetentionClass_RETENTION_CLASS_RESPONSES, Days: 90},
	}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	prompts := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "crew_runs", count: Count{Older: 7, Eligible: 7}}, removed: 2}
	responses := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_RESPONSES, store: "crew_runs", count: Count{Older: 2, Eligible: 2}}, removed: 2}

	rep, err := auditedSweeper(t, st, []Source{prompts, responses}, nil).Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n := len(prompts.calls) + len(responses.calls); n != 1 {
		t.Fatalf("crew_runs was removed %d times, want once", n)
	}
	if len(responses.calls) != 1 {
		t.Fatalf("the removal ran through the prompts source, want the longer (responses) window's")
	}
	if want := fixedNow().AddDate(0, 0, -90); !responses.calls[0].cutoff.Equal(want) {
		t.Errorf("crew_runs cutoff = %v, want %v (the longer 90-day window)", responses.calls[0].cutoff, want)
	}
	if got := findStore(t, rep, pb.RetentionClass_RETENTION_CLASS_RESPONSES, "crew_runs"); got.GetRemoved() != 2 {
		t.Errorf("responses entry removed = %d, want 2 (it carries the deletion)", got.GetRemoved())
	}
	short := findStore(t, rep, pb.RetentionClass_RETENTION_CLASS_PROMPTS, "crew_runs")
	if short.GetRemoved() != 0 || !strings.Contains(short.GetNote(), "RETENTION_CLASS_RESPONSES") {
		t.Errorf("prompts entry = %v, want nothing removed and a note naming the deciding class", short)
	}
}

func TestSweeper_ACountOnlySourceIsLeftAlone(t *testing.T) {
	src := &fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 1, Eligible: 1}}
	rep, err := auditedSweeper(t, enforcing(t), []Source{src}, nil).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got := findStore(t, rep, src.class, "agent_tasks"); got.GetStatus() != pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_COUNTED || got.GetRemoved() != 0 {
		t.Errorf("entry = %v, want counted and nothing removed", got)
	}
}

func TestSweeper_ARemoveFailureIsReportedAndDoesNotStopTheRest(t *testing.T) {
	bad := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 1, Eligible: 1}}, removeErr: errors.New("deadlock detected")}
	good := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_RESPONSES, store: "agent_task_results", count: Count{Older: 2, Eligible: 2}}, removed: 2}
	rep, err := auditedSweeper(t, enforcing(t), []Source{bad, good}, nil).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	b := findStore(t, rep, bad.class, "agent_tasks")
	if b.GetStatus() != pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_ERROR || !strings.Contains(b.GetNote(), "deadlock detected") || b.GetRemoved() != 0 {
		t.Errorf("failed store = %v", b)
	}
	if g := findStore(t, rep, good.class, "agent_task_results"); g.GetRemoved() != 2 {
		t.Errorf("good store = %v, want 2 removed", g)
	}
}

func TestSweeper_EnforceAuditsOncePerSweepBeforeRemovingAnything(t *testing.T) {
	var events []string
	a := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 1, Eligible: 1}}, removed: 1, log: &events}
	b := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_RESPONSES, store: "agent_task_results", count: Count{Older: 2, Eligible: 2}}, removed: 2, log: &events}
	sw := newTestSweeper(t, enforcing(t), []Source{a, b}, nil)
	var seen *pb.RetentionReport
	sw.SetAuditor(func(_ context.Context, rep *pb.RetentionReport) error {
		events = append(events, "audit")
		seen = rep
		return nil
	})
	if _, err := sw.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got := strings.Join(events, " "); got != "audit remove:agent_tasks remove:agent_task_results" {
		t.Errorf("event order = %q, want one audit before both removals", got)
	}
	if seen.GetStores()[0].GetEligible() != 1 || seen.GetStores()[1].GetEligible() != 2 {
		t.Errorf("audit saw %v, want the per-class eligible counts", seen.GetStores())
	}
}

func TestSweeper_AFailedAuditWriteStopsTheRemoval(t *testing.T) {
	src := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 1, Eligible: 1}}, removed: 1}
	sw := newTestSweeper(t, enforcing(t), []Source{src}, nil)
	sw.SetAuditor(func(context.Context, *pb.RetentionReport) error { return errors.New("audit down") })
	if _, err := sw.Sweep(context.Background()); err == nil || !strings.Contains(err.Error(), "audit down") {
		t.Fatalf("Sweep = %v, want the audit error", err)
	}
	if len(src.calls) != 0 {
		t.Errorf("Remove ran %d times after a failed audit write, want never", len(src.calls))
	}
}

func TestReporter_APreviewDoesNotReplaceAnEnforcedReport(t *testing.T) {
	ctx := context.Background()
	src := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 3, Eligible: 3}}, removed: 3}
	r := NewReporter(auditedSweeper(t, enforcing(t), []Source{src}, nil))
	if _, err := r.sweep(ctx); err != nil {
		t.Fatal(err)
	}
	fresh, err := r.Report(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.GetEnforced() {
		t.Error("the refresh report claims it enforced; a refresh must be count-only")
	}
	if kept := r.Last(); !kept.GetEnforced() || kept.GetStores()[0].GetRemoved() != 3 {
		t.Errorf("kept report = %v, want the enforced sweep's evidence kept", kept)
	}
	if len(src.calls) != 1 {
		t.Errorf("Remove ran %d times, want only the periodic sweep's", len(src.calls))
	}
}

// Without an auditor an enforced sweep would delete data with no record of it,
// so it deletes nothing and says why.
func TestSweeper_EnforceWithoutAnAuditorRemovesNothing(t *testing.T) {
	src := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 2, Eligible: 2}}, removed: 2}
	_, err := newTestSweeper(t, enforcing(t), []Source{src}, nil).Sweep(context.Background())
	if err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("Sweep = %v, want an error naming the missing audit store", err)
	}
	if len(src.calls) != 0 {
		t.Errorf("Remove ran %d times with no auditor wired, want never", len(src.calls))
	}
}

// DRY_RUN needs no auditor: it records nothing because it changes nothing.
func TestSweeper_DryRunWithoutAnAuditorStillCounts(t *testing.T) {
	src := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 2, Eligible: 2}}}
	if _, err := newTestSweeper(t, NewMemoryStore(), []Source{src}, nil).Sweep(context.Background()); err != nil {
		t.Fatalf("dry-run Sweep with no auditor: %v", err)
	}
}

// An hourly sweep that finds nothing to delete writes no audit entry.
func TestSweeper_NothingEligibleWritesNoAuditEntryAndRemovesNothing(t *testing.T) {
	src := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 3, Eligible: 0}}}
	audited := 0
	sw := newTestSweeper(t, enforcing(t), []Source{src}, nil)
	sw.SetAuditor(func(context.Context, *pb.RetentionReport) error { audited++; return nil })
	rep, err := sw.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if audited != 0 || len(src.calls) != 0 {
		t.Errorf("audited %d times and removed %d times with nothing eligible, want neither", audited, len(src.calls))
	}
	if !rep.GetEnforced() {
		t.Error("the sweep ran in ENFORCE mode and found nothing; the report should still say so")
	}
}

// A store that could not remove (a missing table) says so on its entry.
func TestSweeper_ASkippedRemovalIsNotedOnTheEntry(t *testing.T) {
	src := &removerSource{fakeSource: fakeSource{class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, store: "agent_tasks", count: Count{Older: 2, Eligible: 2}},
		skipped: `relation "retention_legal_holds" does not exist`}
	rep, err := auditedSweeper(t, enforcing(t), []Source{src}, nil).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	got := findStore(t, rep, src.class, "agent_tasks")
	if got.GetRemoved() != 0 || !strings.Contains(got.GetNote(), "not removed") || !strings.Contains(got.GetNote(), "retention_legal_holds") {
		t.Errorf("entry = %v, want nothing removed and a note saying why", got)
	}
}
