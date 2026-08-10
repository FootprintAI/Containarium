package server

import (
	"sync"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The store hands out copies, not the entry it holds.
//
// Without this, a run stored while it is still being driven is the same
// object the driver keeps writing to, so GetCrewRun can observe it mid-write.
// A proto message is several fields and nothing makes updating them atomic —
// a reader could see COMPLETED with the error text of a failure still set.
func TestCrewRunStore_MutatingWhatYouPutDoesNotChangeWhatIsStored(t *testing.T) {
	s := newCrewRunStore()
	run := &pb.CrewRun{Id: "r1", State: pb.CrewRunState_CREW_RUN_STATE_RUNNING}
	s.put(run)

	run.State = pb.CrewRunState_CREW_RUN_STATE_FAILED
	run.Error = "not yet stored"

	got, ok := s.get("r1")
	if !ok {
		t.Fatal("run vanished")
	}
	if got.State != pb.CrewRunState_CREW_RUN_STATE_RUNNING {
		t.Errorf("state = %v, want RUNNING — the caller's later writes leaked into the store",
			got.State)
	}
	if got.Error != "" {
		t.Errorf("error = %q, want empty", got.Error)
	}
}

// The same in the other direction: what a reader gets back cannot be used to
// corrupt the store for the next reader.
func TestCrewRunStore_MutatingWhatYouGetDoesNotChangeWhatIsStored(t *testing.T) {
	s := newCrewRunStore()
	s.put(&pb.CrewRun{Id: "r1", State: pb.CrewRunState_CREW_RUN_STATE_COMPLETED})

	first, _ := s.get("r1")
	first.State = pb.CrewRunState_CREW_RUN_STATE_FAILED
	first.Error = "scribbled by a reader"

	second, _ := s.get("r1")
	if second.State != pb.CrewRunState_CREW_RUN_STATE_COMPLETED || second.Error != "" {
		t.Errorf("a reader's edits changed the stored run: state=%v error=%q",
			second.State, second.Error)
	}
}

// A later put replaces the entry, which is how a run reaches its terminal
// state after being recorded as RUNNING.
func TestCrewRunStore_PutReplacesTheEntry(t *testing.T) {
	s := newCrewRunStore()
	s.put(&pb.CrewRun{Id: "r1", State: pb.CrewRunState_CREW_RUN_STATE_RUNNING})
	s.put(&pb.CrewRun{Id: "r1", State: pb.CrewRunState_CREW_RUN_STATE_COMPLETED, ArtifactJson: "{}"})

	got, _ := s.get("r1")
	if got.State != pb.CrewRunState_CREW_RUN_STATE_COMPLETED {
		t.Errorf("state = %v, want COMPLETED", got.State)
	}
	if got.ArtifactJson != "{}" {
		t.Errorf("artifact = %q, want the terminal one", got.ArtifactJson)
	}
}

// The hazard the clone exists for: a run is recorded while it is still being
// driven, so the driver goes on mutating the very object it handed the store
// while GetCrewRun reads it.
//
// The writer here mutates the run it already put — not a fresh one — because
// that is what crew_server.go does. A version of this test whose writer puts
// new objects each time proves nothing: the map is mutex-guarded either way,
// and the race is in the shared message, not the map. Run with -race.
func TestCrewRunStore_DriverMutationsDoNotRaceWithReaders(t *testing.T) {
	s := newCrewRunStore()
	run := &pb.CrewRun{Id: "r1", State: pb.CrewRunState_CREW_RUN_STATE_RUNNING}
	s.put(run)

	// A start barrier, so readers and the writer genuinely overlap. Without
	// one the writer's loop can finish before any reader is scheduled, and
	// the test passes whether or not the store clones — which is the version
	// of this test I wrote first, and it did.
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 2000; j++ {
				if got, ok := s.get("r1"); ok {
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
		// Exactly the crew_server.go shape: keep writing the local run, then
		// re-put it on reaching a terminal state.
		for j := 0; j < 2000; j++ {
			run.State = pb.CrewRunState_CREW_RUN_STATE_COMPLETED
			run.ArtifactJson = "{}"
			run.Error = ""
		}
		s.put(run)
	}()

	close(start)
	wg.Wait()
}

func TestCrewRunStore_NilPutIsIgnored(t *testing.T) {
	s := newCrewRunStore()
	s.put(nil) // must not panic
	if _, ok := s.get(""); ok {
		t.Error("a nil run created an entry")
	}
}
