package server

import (
	"sync"
	"testing"
	"time"
)

// newTestQueue returns a queue with a controllable clock starting at a fixed
// instant, plus a function to advance it.
func newTestQueue() (*agentTaskQueue, func(time.Duration)) {
	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0).UTC()
	q := newAgentTaskQueue()
	q.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}
	return q, advance
}

func TestQueue_EnqueueLeaseComplete(t *testing.T) {
	q, _ := newTestQueue()
	id := q.enqueue("web-researcher", `{"q":"hi"}`)
	if id == "" {
		t.Fatal("enqueue returned empty id")
	}
	if q.depth() != 1 {
		t.Fatalf("depth = %d, want 1", q.depth())
	}

	leased, ok := q.lease("", 0)
	if !ok {
		t.Fatal("expected a task to lease")
	}
	if leased.ID != id || leased.SkillID != "web-researcher" || leased.InputJSON != `{"q":"hi"}` {
		t.Fatalf("leased wrong task: %+v", leased)
	}
	if leased.LeaseToken == "" {
		t.Error("lease token should be non-empty")
	}

	if ok := q.complete(leased.ID, leased.LeaseToken, `{"answer":42}`, ""); !ok {
		t.Fatal("complete with valid token should succeed")
	}
	if q.depth() != 0 {
		t.Fatalf("depth after complete = %d, want 0", q.depth())
	}

	// The outcome is recorded and inspectable.
	r, ok := q.result(id)
	if !ok {
		t.Fatal("completed task should have a recorded result")
	}
	if r.artifactJSON != `{"answer":42}` || r.errMsg != "" || r.skillID != "web-researcher" {
		t.Errorf("recorded result wrong: %+v", r)
	}
}

func TestQueue_LeaseHidesFromOtherWorkers(t *testing.T) {
	q, _ := newTestQueue()
	q.enqueue("s", "a")

	if _, ok := q.lease("", time.Minute); !ok {
		t.Fatal("first lease should succeed")
	}
	// A second worker polling immediately sees nothing — the task is leased.
	if _, ok := q.lease("", time.Minute); ok {
		t.Fatal("second lease should find nothing (task is held)")
	}
}

func TestQueue_RedeliversAfterLeaseExpiry(t *testing.T) {
	q, advance := newTestQueue()
	q.enqueue("s", "a")

	first, ok := q.lease("", 30*time.Second)
	if !ok {
		t.Fatal("first lease should succeed")
	}
	// Still inside the lease window: invisible.
	advance(20 * time.Second)
	if _, ok := q.lease("", 30*time.Second); ok {
		t.Fatal("task should still be hidden inside the lease window")
	}
	// Past expiry: redelivered with a NEW token.
	advance(15 * time.Second)
	second, ok := q.lease("", 30*time.Second)
	if !ok {
		t.Fatal("task should be redelivered after lease expiry")
	}
	if second.LeaseToken == first.LeaseToken {
		t.Error("redelivery must mint a fresh lease token")
	}

	// The slow original worker now completes with its STALE token — rejected,
	// because the redelivered lease owns the task.
	if ok := q.complete(first.ID, first.LeaseToken, "late", ""); ok {
		t.Error("stale-token completion must be rejected")
	}
	// The current lease holder completes successfully.
	if ok := q.complete(second.ID, second.LeaseToken, "ok", ""); !ok {
		t.Error("current-token completion must succeed")
	}
}

func TestQueue_SkillFilter(t *testing.T) {
	q, _ := newTestQueue()
	q.enqueue("alpha", "1")
	q.enqueue("beta", "2")

	// A worker scoped to "beta" skips the alpha task at the head.
	leased, ok := q.lease("beta", time.Minute)
	if !ok || leased.SkillID != "beta" {
		t.Fatalf("filtered lease should return the beta task, got ok=%v %+v", ok, leased)
	}
	// "alpha" is still leasable.
	a, ok := q.lease("alpha", time.Minute)
	if !ok || a.SkillID != "alpha" {
		t.Fatalf("alpha task should be leasable, got ok=%v %+v", ok, a)
	}
}

func TestQueue_FIFOAndEmpty(t *testing.T) {
	q, _ := newTestQueue()
	if _, ok := q.lease("", 0); ok {
		t.Fatal("empty queue should lease nothing")
	}
	id1 := q.enqueue("s", "1")
	id2 := q.enqueue("s", "2")
	l1, _ := q.lease("", time.Minute)
	l2, _ := q.lease("", time.Minute)
	if l1.ID != id1 || l2.ID != id2 {
		t.Errorf("FIFO violated: got %s then %s, want %s then %s", l1.ID, l2.ID, id1, id2)
	}
}

func TestQueue_DoubleCompleteRejected(t *testing.T) {
	q, _ := newTestQueue()
	q.enqueue("s", "a")
	l, _ := q.lease("", time.Minute)
	if ok := q.complete(l.ID, l.LeaseToken, "first", ""); !ok {
		t.Fatal("first complete should succeed")
	}
	// Re-completing a gone task is a no-op, not a panic.
	if ok := q.complete(l.ID, l.LeaseToken, "second", ""); ok {
		t.Error("completing an already-removed task must return false")
	}
}

func TestQueue_ConcurrentLeasesAreUnique(t *testing.T) {
	q := newAgentTaskQueue() // real clock is fine; we only test mutual exclusion
	const n = 50
	for i := 0; i < n; i++ {
		q.enqueue("s", "x")
	}
	var mu sync.Mutex
	seen := map[string]bool{}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l, ok := q.lease("", time.Minute); ok {
				mu.Lock()
				if seen[l.ID] {
					t.Errorf("task %s leased twice concurrently", l.ID)
				}
				seen[l.ID] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != n {
		t.Errorf("leased %d distinct tasks, want %d", len(seen), n)
	}
}
