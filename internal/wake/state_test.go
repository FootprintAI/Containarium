package wake

import (
	"fmt"
	"sync"
	"testing"
)

// TestWakeStateTracker_BasicConcurrency — 10 goroutines independently
// mark + clear different container names, plus a race-y reader. After
// all goroutines finish, the tracker should be empty (every Mark was
// paired with a Clear). Run with `-race` to also catch the obvious
// "forgot the lock" bugs in the map.
func TestWakeStateTracker_BasicConcurrency(t *testing.T) {
	tracker := New()

	const goroutines = 10
	const iterations = 100

	// Writers' waitgroup. The reader runs on a separate channel so
	// closing `stop` doesn't deadlock waiting for it to react.
	var writers sync.WaitGroup
	writers.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer writers.Done()
			name := fmt.Sprintf("container-%d", id)
			for j := 0; j < iterations; j++ {
				tracker.MarkWakeMode(name, "sub", "10.0.3.1", 8080)
				if _, _, ok := tracker.IsInWakeMode(name); !ok {
					t.Errorf("expected %s in wake mode after Mark", name)
				}
				tracker.ClearWakeMode(name)
			}
		}(i)
	}

	// Concurrent reader — exercises the RWMutex against the writers.
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stop:
				return
			default:
				_ = tracker.Snapshot()
			}
		}
	}()

	writers.Wait()
	close(stop)
	<-readerDone

	if got := len(tracker.Snapshot()); got != 0 {
		t.Errorf("expected empty tracker after balanced Mark/Clear, got %d entries", got)
	}
}

// TestWakeStateTracker_MarkOverwrites — calling MarkWakeMode twice for
// the same container should leave the latest entry. Idempotency
// matters because StopForAutoSleep can fire repeatedly under load.
func TestWakeStateTracker_MarkOverwrites(t *testing.T) {
	tracker := New()
	tracker.MarkWakeMode("alice-container", "alice-sub-old", "10.0.3.1", 8080)
	tracker.MarkWakeMode("alice-container", "alice-sub-new", "10.0.3.2", 9090)
	host, port, ok := tracker.IsInWakeMode("alice-container")
	if !ok {
		t.Fatalf("expected alice-container in wake mode")
	}
	if host != "10.0.3.2" || port != 9090 {
		t.Errorf("expected host=10.0.3.2 port=9090, got host=%s port=%d", host, port)
	}
	entry, ok := tracker.Entry("alice-container")
	if !ok || entry.Subdomain != "alice-sub-new" {
		t.Errorf("expected latest subdomain in entry, got %+v ok=%v", entry, ok)
	}
}

// TestWakeStateTracker_ClearMissingIsNoOp — clearing a container that
// was never marked must not panic.
func TestWakeStateTracker_ClearMissingIsNoOp(t *testing.T) {
	tracker := New()
	tracker.ClearWakeMode("does-not-exist")
	if got := len(tracker.Snapshot()); got != 0 {
		t.Errorf("expected empty tracker, got %d entries", got)
	}
}
