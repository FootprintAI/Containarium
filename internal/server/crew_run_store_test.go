package server

import (
	"context"
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
