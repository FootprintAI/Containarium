package server

import (
	"context"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Ownership of stranded-run reconciliation (#1322, part 2's third criterion).
//
// The sweep marks every RUNNING run FAILED at daemon start, because a run the
// previous daemon was driving has no resumption point. That is right for a
// single daemon and wrong the moment two share one Postgres — which the peer
// pool makes a real topology: daemon B restarting would mark daemon A's
// in-flight runs FAILED while A is still driving them.
//
// #1322 named this and asked for the design decision to be written down
// before code. It is: a run records the daemon that owns it, and the sweep
// fails runs that are THIS daemon's or unowned — never a peer's. A peer's run
// is that peer's to reconcile, on its own restart.
//
// Deliberately NOT a heartbeat. A heartbeat would additionally reap runs whose
// owner died permanently, at the cost of a liveness protocol and a timeout to
// tune wrongly. Owner-scoping is strictly better than today and cannot fail a
// peer's live run; the permanently-dead-owner case stays visible as a run that
// never terminates, rather than being guessed at.

func TestMemCrewRunStore_FailStrandedOnlyFailsItsOwnRuns(t *testing.T) {
	ctx := context.Background()
	s := NewMemCrewRunStore()

	mine := &pb.CrewRun{Id: "mine", State: pb.CrewRunState_CREW_RUN_STATE_RUNNING, Owner: "vm-a"}
	theirs := &pb.CrewRun{Id: "theirs", State: pb.CrewRunState_CREW_RUN_STATE_RUNNING, Owner: "vm-b"}
	for _, r := range []*pb.CrewRun{mine, theirs} {
		if err := s.Put(ctx, r); err != nil {
			t.Fatalf("Put(%s): %v", r.Id, err)
		}
	}

	n, err := s.FailStranded(ctx, "vm-a", StrandedByRestart)
	if err != nil {
		t.Fatalf("FailStranded: %v", err)
	}
	if n != 1 {
		t.Errorf("failed %d run(s), want 1", n)
	}

	got, _, err := s.Get(ctx, "theirs")
	if err != nil {
		t.Fatalf("Get(theirs): %v", err)
	}
	if got.State != pb.CrewRunState_CREW_RUN_STATE_RUNNING {
		t.Errorf("a peer's in-flight run was marked %v by THIS daemon's restart — vm-b is still "+
			"driving it, and its caller now sees a failure that did not happen", got.State)
	}

	own, _, err := s.Get(ctx, "mine")
	if err != nil {
		t.Fatalf("Get(mine): %v", err)
	}
	if own.State != pb.CrewRunState_CREW_RUN_STATE_FAILED {
		t.Errorf("this daemon's own stranded run is %v, want FAILED — it has no resumption point "+
			"and would answer RUNNING forever", own.State)
	}
}

// A run with no recorded owner predates ownership, and is still swept.
//
// This is the deliberate half of the design. Leaving them would strand every
// pre-upgrade run forever, reintroducing #1182 for exactly the rows the
// reconciliation exists for — and on the single-daemon deployment that is the
// default, an unowned run is always this daemon's own. The bounded risk is a
// multi-daemon deployment's FIRST restart after upgrade, where a peer's
// pre-upgrade run could be swept once; after that every run carries an owner
// and peers are protected permanently.
func TestMemCrewRunStore_FailStrandedStillSweepsUnownedRuns(t *testing.T) {
	ctx := context.Background()
	s := NewMemCrewRunStore()

	if err := s.Put(ctx, &pb.CrewRun{Id: "legacy", State: pb.CrewRunState_CREW_RUN_STATE_RUNNING}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	n, err := s.FailStranded(ctx, "vm-a", StrandedByRestart)
	if err != nil {
		t.Fatalf("FailStranded: %v", err)
	}
	if n != 1 {
		t.Errorf("failed %d run(s), want 1 — a run written before ownership existed would "+
			"otherwise answer RUNNING forever, which is the bug reconciliation exists to fix", n)
	}
}
