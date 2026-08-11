package server

import (
	"context"
	"testing"
	"time"
)

// #1182 shipped CrewRunStore/AgentTaskQueue with Postgres impls in #1316 and
// #1318 — and nothing constructed them. The interfaces existed, the SQL
// existed, and the daemon kept using the in-memory defaults, so a restart
// still lost every run. The durability was unreachable.
//
// These pin the swap seam the daemon relies on. They can't prove dual_server
// calls it (that needs a live Postgres), but they do prove the setters exist
// and take effect — the part that was missing.

func TestCrewServer_SetRunStoreTakesEffect(t *testing.T) {
	s := NewCrewServer(nil)
	swapped := NewMemCrewRunStore()
	s.SetRunStore(swapped)
	if s.runs != CrewRunStore(swapped) {
		t.Fatal("SetRunStore did not replace the store")
	}
}

// A nil store must not blank out a working one: the daemon calls the setter
// from a best-effort branch, and losing the in-memory fallback would leave the
// server with no store at all.
func TestCrewServer_SetRunStoreIgnoresNil(t *testing.T) {
	s := NewCrewServer(nil)
	before := s.runs
	s.SetRunStore(nil)
	if s.runs == nil || s.runs != before {
		t.Error("SetRunStore(nil) cleared the existing store")
	}
}

func TestAgentSkillServer_SetTaskQueueTakesEffect(t *testing.T) {
	s := &AgentSkillServer{queue: NewMemAgentTaskQueue()}
	swapped := NewMemAgentTaskQueue()
	s.SetTaskQueue(swapped)
	if s.queue != AgentTaskQueue(swapped) {
		t.Fatal("SetTaskQueue did not replace the queue")
	}

	// And the swapped queue is the one actually used.
	if _, err := s.queue.Enqueue(context.Background(), "s", ""); err != nil {
		t.Fatalf("Enqueue on swapped queue: %v", err)
	}
	if d, _ := swapped.Depth(context.Background()); d != 1 {
		t.Errorf("swapped queue depth = %d, want 1 — writes went elsewhere", d)
	}
	if _, ok, _ := swapped.Lease(context.Background(), "", time.Minute); !ok {
		t.Error("swapped queue had nothing leasable")
	}
}

func TestAgentSkillServer_SetTaskQueueIgnoresNil(t *testing.T) {
	s := &AgentSkillServer{queue: NewMemAgentTaskQueue()}
	before := s.queue
	s.SetTaskQueue(nil)
	if s.queue == nil || s.queue != before {
		t.Error("SetTaskQueue(nil) cleared the existing queue")
	}
}
