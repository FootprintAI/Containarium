package server

import (
	"context"
	"sync"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// These run against MemCrewRunStore. The Postgres impl satisfies the same
// interface and is covered by the integration lane (a real DB), so the
// behavioral contract lives here once rather than being restated per backend.

func TestMemCrewRunStore_PutGetRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewMemCrewRunStore()

	want := &pb.CrewRun{
		Id:        "crewrun-abc",
		CrewId:    "research",
		TraceId:   "abc",
		State:     pb.CrewRunState_CREW_RUN_STATE_RUNNING,
		InputJson: `{"q":"hello"}`,
	}
	if err := s.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok, err := s.Get(ctx, "crewrun-abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("run not found after Put")
	}
	if got.GetCrewId() != "research" || got.GetState() != pb.CrewRunState_CREW_RUN_STATE_RUNNING {
		t.Errorf("round trip lost fields: %+v", got)
	}
	if got.GetInputJson() != `{"q":"hello"}` {
		t.Errorf("input_json = %q", got.GetInputJson())
	}
}

func TestMemCrewRunStore_GetMissing(t *testing.T) {
	got, ok, err := NewMemCrewRunStore().Get(context.Background(), "nope")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok || got != nil {
		t.Errorf("want (nil,false), got (%v,%v)", got, ok)
	}
}

// The store must clone on the way in. RunCrew records a run and then keeps
// mutating the same pointer as the crew progresses; if the store held that
// pointer, a reader would observe fields mid-write.
func TestMemCrewRunStore_ClonesOnPut(t *testing.T) {
	ctx := context.Background()
	s := NewMemCrewRunStore()

	run := &pb.CrewRun{Id: "r1", State: pb.CrewRunState_CREW_RUN_STATE_RUNNING}
	if err := s.Put(ctx, run); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Mutate the caller's copy exactly as RunCrew does after recording.
	run.State = pb.CrewRunState_CREW_RUN_STATE_FAILED
	run.Error = "boom"

	got, _, err := s.Get(ctx, "r1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.GetState() != pb.CrewRunState_CREW_RUN_STATE_RUNNING {
		t.Errorf("stored run tracked a post-Put mutation: state = %v, want RUNNING", got.GetState())
	}
	if got.GetError() != "" {
		t.Errorf("stored run tracked a post-Put mutation: error = %q", got.GetError())
	}
}

// And on the way out, or a caller mutating what Get returned would corrupt
// the stored copy for everyone else.
func TestMemCrewRunStore_ClonesOnGet(t *testing.T) {
	ctx := context.Background()
	s := NewMemCrewRunStore()
	if err := s.Put(ctx, &pb.CrewRun{Id: "r1", State: pb.CrewRunState_CREW_RUN_STATE_RUNNING}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	first, _, err := s.Get(ctx, "r1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	first.State = pb.CrewRunState_CREW_RUN_STATE_CANCELLED

	second, _, err := s.Get(ctx, "r1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if second.GetState() != pb.CrewRunState_CREW_RUN_STATE_RUNNING {
		t.Errorf("mutating a Get result changed the stored run: %v", second.GetState())
	}
}

// Put is an upsert keyed by id — RunCrew calls it repeatedly for one run as it
// moves RUNNING -> COMPLETED.
func TestMemCrewRunStore_PutOverwrites(t *testing.T) {
	ctx := context.Background()
	s := NewMemCrewRunStore()

	if err := s.Put(ctx, &pb.CrewRun{Id: "r1", State: pb.CrewRunState_CREW_RUN_STATE_RUNNING}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Put(ctx, &pb.CrewRun{
		Id: "r1", State: pb.CrewRunState_CREW_RUN_STATE_COMPLETED, ArtifactJson: `{"ok":true}`,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, _, err := s.Get(ctx, "r1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.GetState() != pb.CrewRunState_CREW_RUN_STATE_COMPLETED {
		t.Errorf("state = %v, want COMPLETED", got.GetState())
	}
	if got.GetArtifactJson() != `{"ok":true}` {
		t.Errorf("artifact_json = %q", got.GetArtifactJson())
	}
}

// A nil run is a no-op rather than a panic — RunCrew's error paths are the
// kind of code that grows a nil.
func TestMemCrewRunStore_PutNil(t *testing.T) {
	if err := NewMemCrewRunStore().Put(context.Background(), nil); err != nil {
		t.Errorf("Put(nil) = %v, want nil", err)
	}
}

// CrewRunStore is the contract the daemon wires; both impls must satisfy it.
var _ CrewRunStore = (*MemCrewRunStore)(nil)
var _ CrewRunStore = (*PostgresCrewRunStore)(nil)

// The hazard the clone exists for, which the other tests in this file do not
// reach: RunCrew records the run before driving it (crew_server.go), so the
// driver goes on mutating the very object it handed the store while
// GetCrewRun reads it. A CrewRun is several fields and nothing makes updating
// them atomic.
//
// This covered #1298 and was lost when the store moved behind an interface —
// the clone survived, the test for it under concurrency did not. Run with
// -race.
//
// Two details it needs to mean anything, both learned by getting them wrong:
// the writer mutates the run it already Put rather than putting fresh ones
// (the map is mutex-guarded either way; the race is in the shared message),
// and a start barrier makes readers and writer actually overlap. Without the
// barrier the writer finishes before any reader is scheduled and the test
// passes with the clone removed.
func TestMemCrewRunStore_DriverMutationsDoNotRaceWithReaders(t *testing.T) {
	ctx := context.Background()
	s := NewMemCrewRunStore()

	run := &pb.CrewRun{Id: "r1", State: pb.CrewRunState_CREW_RUN_STATE_RUNNING}
	if err := s.Put(ctx, run); err != nil {
		t.Fatalf("put: %v", err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 2000; j++ {
				if got, ok, err := s.Get(ctx, "r1"); err == nil && ok {
					_ = got.State
					_ = got.Error
					_ = got.ArtifactJson
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for j := 0; j < 2000; j++ {
			run.State = pb.CrewRunState_CREW_RUN_STATE_COMPLETED
			run.ArtifactJson = "{}"
			run.Error = ""
		}
		_ = s.Put(ctx, run)
	}()

	close(start)
	wg.Wait()
}

// #1182 AC4: a run left RUNNING across a restart must reach a terminal state.
//
// RunCrew records a run as RUNNING before driving it, and the store is now
// durable, so a daemon that stops mid-run leaves that state behind. Without
// reconciliation GetCrewRun answers RUNNING forever for a run that can never
// finish — a persistent lie about state, which is worse than the old
// behaviour of losing the run entirely.
func TestMemCrewRunStore_FailStrandedTerminatesRunningRuns(t *testing.T) {
	ctx := context.Background()
	s := NewMemCrewRunStore()

	mustPut(t, s, &pb.CrewRun{Id: "in-flight", State: pb.CrewRunState_CREW_RUN_STATE_RUNNING})
	mustPut(t, s, &pb.CrewRun{Id: "done", State: pb.CrewRunState_CREW_RUN_STATE_COMPLETED, ArtifactJson: "{}"})
	mustPut(t, s, &pb.CrewRun{Id: "already-failed", State: pb.CrewRunState_CREW_RUN_STATE_FAILED, Error: "a real failure"})

	n, err := s.FailStranded(ctx, "", StrandedByRestart)
	if err != nil {
		t.Fatalf("FailStranded: %v", err)
	}
	if n != 1 {
		t.Errorf("reconciled %d runs, want 1 — only the in-flight one was stranded", n)
	}

	got, _, _ := s.Get(ctx, "in-flight")
	if got.State != pb.CrewRunState_CREW_RUN_STATE_FAILED {
		t.Errorf("state = %v, want FAILED — a run nothing is driving must not keep claiming to run",
			got.State)
	}
	if got.Error != StrandedByRestart {
		t.Errorf("error = %q, want the restart reason — an operator has to be able to tell this "+
			"from a crew that genuinely failed", got.Error)
	}
}

// Terminal runs must be left exactly as they are: overwriting a completed
// run's artifact, or a failed run's real error, would destroy the record of
// what actually happened.
func TestMemCrewRunStore_FailStrandedLeavesTerminalRunsAlone(t *testing.T) {
	ctx := context.Background()
	s := NewMemCrewRunStore()

	mustPut(t, s, &pb.CrewRun{Id: "done", State: pb.CrewRunState_CREW_RUN_STATE_COMPLETED, ArtifactJson: "{}"})
	mustPut(t, s, &pb.CrewRun{Id: "failed", State: pb.CrewRunState_CREW_RUN_STATE_FAILED, Error: "a real failure"})

	if _, err := s.FailStranded(ctx, "", StrandedByRestart); err != nil {
		t.Fatalf("FailStranded: %v", err)
	}

	done, _, _ := s.Get(ctx, "done")
	if done.State != pb.CrewRunState_CREW_RUN_STATE_COMPLETED || done.ArtifactJson != "{}" {
		t.Errorf("a completed run was altered: state=%v artifact=%q", done.State, done.ArtifactJson)
	}
	failed, _, _ := s.Get(ctx, "failed")
	if failed.Error != "a real failure" {
		t.Errorf("a genuine failure reason was overwritten with the restart reason: %q", failed.Error)
	}
}

// Running it twice must not keep re-reporting the same runs, or a restart loop
// would log a growing number of reconciliations that are not happening.
func TestMemCrewRunStore_FailStrandedIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := NewMemCrewRunStore()
	mustPut(t, s, &pb.CrewRun{Id: "in-flight", State: pb.CrewRunState_CREW_RUN_STATE_RUNNING})

	first, _ := s.FailStranded(ctx, "", StrandedByRestart)
	second, _ := s.FailStranded(ctx, "", StrandedByRestart)
	if first != 1 || second != 0 {
		t.Errorf("counts were %d then %d, want 1 then 0", first, second)
	}
}

func mustPut(t *testing.T, s CrewRunStore, r *pb.CrewRun) {
	t.Helper()
	if err := s.Put(context.Background(), r); err != nil {
		t.Fatalf("put %s: %v", r.GetId(), err)
	}
}
