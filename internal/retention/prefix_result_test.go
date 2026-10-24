package retention

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// resultSweeper is an enforcing sweeper over p whose two audit hooks record
// their calls in order.
func resultSweeper(t *testing.T, p *fakePrefix, events *[]string, results *[]PurgeResult, resultErr error) *Sweeper {
	t.Helper()
	sw := newTestSweeper(t, enforcing(t), nil, chainUnswept())
	sw.SetAuditor(func(context.Context, *pb.RetentionReport) error { *events = append(*events, "audit"); return nil })
	sw.SetResultAuditor(func(_ context.Context, r PurgeResult) error {
		*events = append(*events, "result")
		*results = append(*results, r)
		return resultErr
	})
	p.log = events
	sw.AddPrefixSource(p)
	return sw
}

func TestPrefixResult_APurgeWritesTheResultAfterTheRemovalWithBothBases(t *testing.T) {
	var events []string
	var results []PurgeResult
	p := eligibleChain()
	sw := resultSweeper(t, p, &events, &results, nil)

	if _, err := sw.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if strings.Join(events, ",") != "audit,remove,result" {
		t.Fatalf("events = %v, want the result entry after the removal", events)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.Store != "audit_logs" || r.PreviousBaseID != 10 || r.BaseID != 510 || r.RowsRemoved != 10 {
		t.Errorf("result = %+v, want audit_logs previous base 10, new base 510, 10 rows", r)
	}
	if r.ByClass[gwClass] != 7 || r.ByClass[sessClass] != 3 {
		t.Errorf("by class = %v, want gateway 7 and session 3", r.ByClass)
	}
}

func TestPrefixResult_NoPriorPurgeHasPreviousBaseZero(t *testing.T) {
	var events []string
	var results []PurgeResult
	p := eligibleChain()
	p.count.Base = nil
	sw := resultSweeper(t, p, &events, &results, nil)

	if _, err := sw.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].PreviousBaseID != 0 || results[0].BaseID != 510 {
		t.Fatalf("results = %+v, want previous base 0 and base 510", results)
	}
}

func TestPrefixResult_NothingRemovedWritesNoResult(t *testing.T) {
	for name, removal := range map[string]PrefixRemoval{
		"skipped":      {Skipped: "no anchor"},
		"zero removed": {RemovedByClass: map[pb.RetentionClass]int64{gwClass: 0, sessClass: 0}, Base: chainBase(10)},
	} {
		t.Run(name, func(t *testing.T) {
			var events []string
			var results []PurgeResult
			p := eligibleChain()
			p.removal = removal
			sw := resultSweeper(t, p, &events, &results, nil)

			if _, err := sw.Sweep(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(results) != 0 {
				t.Fatalf("wrote %d result entries although nothing was removed: %+v", len(results), results)
			}
		})
	}
}

func TestPrefixResult_DryRunAndPreviewWriteNeitherEntry(t *testing.T) {
	var events []string
	var results []PurgeResult
	p := eligibleChain()
	sw := newTestSweeper(t, NewMemoryStore(), nil, chainUnswept())
	sw.SetAuditor(func(context.Context, *pb.RetentionReport) error { events = append(events, "audit"); return nil })
	sw.SetResultAuditor(func(_ context.Context, r PurgeResult) error { results = append(results, r); return nil })
	sw.AddPrefixSource(p)

	if _, err := sw.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := sw.Preview(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 || len(results) != 0 || p.removed != 0 {
		t.Fatalf("dry run wrote %d audit and %d result entries and removed %d times, want none", len(events), len(results), p.removed)
	}
}

func TestPrefixResult_AFailedResultWriteDoesNotUndoOrFailThePurge(t *testing.T) {
	var events []string
	var results []PurgeResult
	p := eligibleChain()
	sw := resultSweeper(t, p, &events, &results, errors.New("audit down"))

	rep, err := sw.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep failed because the result entry could not be written: %v", err)
	}
	gw := findStore(t, rep, gwClass, "audit_logs")
	sess := findStore(t, rep, sessClass, "audit_logs")
	if gw.GetRemoved() != 7 || sess.GetRemoved() != 3 || gw.GetChainBase().GetBaseId() != 510 {
		t.Errorf("the purge is committed, so the report must still show it: gw=%d sess=%d base=%v", gw.GetRemoved(), sess.GetRemoved(), gw.GetChainBase())
	}
	for _, e := range []*pb.RetentionStoreReport{gw, sess} {
		if !strings.Contains(e.GetNote(), "retention.sweep.result") || !strings.Contains(e.GetNote(), "audit down") {
			t.Errorf("%v note = %q, want it to name the unwritten result entry and why", e.GetClass(), e.GetNote())
		}
		if e.GetStatus() == pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_ERROR {
			t.Errorf("%v is ERROR; the rows were removed, only the second entry is missing", e.GetClass())
		}
	}
}

func TestPrefixResult_APartialPurgeThatFailedStillWritesWhatWasRemoved(t *testing.T) {
	var events []string
	var results []PurgeResult
	p := eligibleChain()
	p.removeErr = errors.New("purge audit_logs: connection reset")
	p.removal = PrefixRemoval{RemovedByClass: map[pb.RetentionClass]int64{gwClass: 4}, Base: chainBase(300)}
	sw := resultSweeper(t, p, &events, &results, nil)

	if _, err := sw.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].RowsRemoved != 4 || results[0].BaseID != 300 {
		t.Fatalf("results = %+v, want the 4 rows that did go, with base 300", results)
	}
}
