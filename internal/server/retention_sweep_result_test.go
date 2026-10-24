package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/retention"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// chainPrefix is a PrefixSource over a fixed answer for the hash-chained
// audit_logs: a purge that starts from base 10 and ends on base 510.
type chainPrefix struct {
	removals int
	removal  retention.PrefixRemoval
}

func baseOf(id int64) *pb.RetentionChainBase {
	return &pb.RetentionChainBase{BaseId: id, BaseHash: "h", PurgedAt: timestamppb.Now(), RowsPurged: id}
}

func newChainPrefix() *chainPrefix {
	return &chainPrefix{removal: retention.PrefixRemoval{
		RemovedByClass: map[pb.RetentionClass]int64{
			pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS:        7,
			pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS: 3,
		},
		Base: baseOf(510),
	}}
}

func (c *chainPrefix) Store() string { return "audit_logs" }
func (c *chainPrefix) Classes() []pb.RetentionClass {
	return []pb.RetentionClass{pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS, pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS}
}
func (c *chainPrefix) CountPrefix(context.Context, map[pb.RetentionClass]time.Time, []string) (retention.PrefixCount, error) {
	return retention.PrefixCount{
		ByClass: map[pb.RetentionClass]retention.Count{
			pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS:        {Older: 9, Eligible: 7},
			pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS: {Older: 4, Eligible: 3},
		},
		Base: baseOf(10),
	}, nil
}
func (c *chainPrefix) RemovePrefix(context.Context, map[pb.RetentionClass]time.Time, []string, int) (retention.PrefixRemoval, error) {
	c.removals++
	return c.removal, nil
}

// failingAction is an audit logger that refuses one action and records the rest.
type failingAction struct {
	*fakeAuditLogger
	action string
}

func (f failingAction) Log(ctx context.Context, e *audit.AuditEntry) error {
	if e.Action == f.action {
		return errors.New("audit store down")
	}
	return f.fakeAuditLogger.Log(ctx, e)
}

// sweepOnce runs one start-up sweep of the reporter, as the daemon does.
func sweepOnce(t *testing.T, r *retention.Reporter) *pb.RetentionReport {
	t.Helper()
	prev := r.Last()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx, time.Hour); close(done) }()
	deadline := time.After(5 * time.Second)
	for r.Last() == prev {
		select {
		case <-deadline:
			t.Fatal("no sweep ran")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	return r.Last()
}

// purgeServer wires a RetentionServer, an audit logger and a reporter over the
// fake chain, in the given mode.
func purgeServer(t *testing.T, mode pb.RetentionMode, logger auditLogger) (*retention.Reporter, *chainPrefix) {
	t.Helper()
	store := retention.NewMemoryStore()
	if _, err := store.SetMode(context.Background(), mode, "ops", nil); err != nil {
		t.Fatal(err)
	}
	chain := newChainPrefix()
	reporter := retention.NewReporter(retention.NewSweeper(store, nil, nil))
	reporter.AddPrefixSource(chain)
	s, _ := newRetentionTestServer()
	s.SetStore(store)
	s.SetAuditStore(logger)
	s.SetReporter(reporter)
	return reporter, chain
}

func TestRetentionServer_APrefixPurgeWritesTheSweepEntryWithItsStartingBaseAndAResultWithTheNewBase(t *testing.T) {
	a := &fakeAuditLogger{}
	reporter, chain := purgeServer(t, pb.RetentionMode_RETENTION_MODE_ENFORCE, a)

	sweepOnce(t, reporter)

	if chain.removals != 1 {
		t.Fatalf("the chain was purged %d times, want 1", chain.removals)
	}
	sweeps := a.byAction(retentionSweepAction)
	if len(sweeps) != 1 {
		t.Fatalf("got %d retention.sweep entries, want 1 (the pre-delete entry is unchanged)", len(sweeps))
	}
	var sd retentionSweepAuditDetail
	if err := json.Unmarshal([]byte(sweeps[0].Detail), &sd); err != nil {
		t.Fatal(err)
	}
	if len(sd.Stores) == 0 {
		t.Fatalf("sweep entry names no stores: %s", sweeps[0].Detail)
	}
	for _, st := range sd.Stores {
		if st.Store == "audit_logs" && st.PreviousBaseID != 10 {
			t.Errorf("%s previous_base_id = %d, want the base the purge starts from (10)", st.Class, st.PreviousBaseID)
		}
	}

	results := a.byAction(retentionSweepResultAction)
	if len(results) != 1 {
		t.Fatalf("got %d retention.sweep.result entries, want 1", len(results))
	}
	if results[0].Username != retentionSweeperActor {
		t.Errorf("result entry by %q, want %q", results[0].Username, retentionSweeperActor)
	}
	var d retentionSweepResultAuditDetail
	if err := json.Unmarshal([]byte(results[0].Detail), &d); err != nil {
		t.Fatalf("detail: %v", err)
	}
	if d.Store != "audit_logs" || d.PreviousBaseID != 10 || d.BaseID != 510 || d.RowsRemoved != 10 || len(d.Classes) != 2 {
		t.Errorf("result detail = %+v, want audit_logs, previous 10, base 510, 10 rows, 2 classes", d)
	}
	if strings.Contains(results[0].Detail, "hash") {
		t.Errorf("result detail carries a hash, want ids and counts only: %s", results[0].Detail)
	}
}

func TestRetentionServer_AFailedResultEntryLeavesThePurgeCommittedAndIsReported(t *testing.T) {
	a := &fakeAuditLogger{}
	reporter, chain := purgeServer(t, pb.RetentionMode_RETENTION_MODE_ENFORCE, failingAction{a, retentionSweepResultAction})

	rep := sweepOnce(t, reporter)

	if chain.removals != 1 || len(a.byAction(retentionSweepAction)) != 1 {
		t.Fatalf("purges = %d, sweep entries = %d, want 1 and 1: a result entry that cannot be written must not stop or undo the purge", chain.removals, len(a.byAction(retentionSweepAction)))
	}
	if n := len(a.byAction(retentionSweepResultAction)); n != 0 {
		t.Fatalf("recorded %d result entries although the store refused them", n)
	}
	for _, st := range rep.GetStores() {
		if st.GetStore() != "audit_logs" {
			continue
		}
		if st.GetStatus() == pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_ERROR || st.GetRemoved() == 0 {
			t.Errorf("%v status=%v removed=%d, want the removal reported as done", st.GetClass(), st.GetStatus(), st.GetRemoved())
		}
		if !strings.Contains(st.GetNote(), "retention.sweep.result") {
			t.Errorf("%v note = %q, want it to say the result entry was not written", st.GetClass(), st.GetNote())
		}
	}
}

func TestRetentionServer_NoResultEntryWhenNothingWasRemovedOrInDryRun(t *testing.T) {
	t.Run("nothing removed", func(t *testing.T) {
		a := &fakeAuditLogger{}
		reporter, chain := purgeServer(t, pb.RetentionMode_RETENTION_MODE_ENFORCE, a)
		chain.removal = retention.PrefixRemoval{Skipped: "no published anchor"}

		sweepOnce(t, reporter)

		if n := len(a.byAction(retentionSweepResultAction)); n != 0 {
			t.Fatalf("wrote %d result entries although nothing was removed", n)
		}
	})
	t.Run("dry run", func(t *testing.T) {
		a := &fakeAuditLogger{}
		reporter, chain := purgeServer(t, pb.RetentionMode_RETENTION_MODE_DRY_RUN, a)

		sweepOnce(t, reporter)

		if chain.removals != 0 || len(a.byAction(retentionSweepAction)) != 0 || len(a.byAction(retentionSweepResultAction)) != 0 {
			t.Fatalf("a dry run purged %d times and wrote %d sweep and %d result entries, want none",
				chain.removals, len(a.byAction(retentionSweepAction)), len(a.byAction(retentionSweepResultAction)))
		}
	})
}
