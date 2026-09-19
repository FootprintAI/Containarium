package runlease

import (
	"sync"
	"testing"
)

func TestRegistry_RegisterThenGet(t *testing.T) {
	r := NewRegistry()
	r.Register("run-1", Info{SkillID: "code-review", Model: "sonnet"})

	got, ok := r.Get("run-1")
	if !ok {
		t.Fatal("Get(run-1) = not found, want found")
	}
	if got.SkillID != "code-review" || got.Model != "sonnet" {
		t.Errorf("Get(run-1) = %+v, want {code-review sonnet}", got)
	}
}

func TestRegistry_Live(t *testing.T) {
	r := NewRegistry()
	if r.Live("run-1") {
		t.Error("Live(run-1) = true before Register")
	}
	r.Register("run-1", Info{SkillID: "s"})
	if !r.Live("run-1") {
		t.Error("Live(run-1) = false after Register")
	}
	r.Unregister("run-1")
	if r.Live("run-1") {
		t.Error("Live(run-1) = true after Unregister")
	}
}

func TestRegistry_UnregisterUnknownRunIsANoOp(t *testing.T) {
	r := NewRegistry()
	r.Unregister("never-registered") // must not panic
	if r.Live("never-registered") {
		t.Error("an unregistered run reports Live")
	}
}

func TestRegistry_GetUnknownRun(t *testing.T) {
	r := NewRegistry()
	if _, ok := r.Get("nope"); ok {
		t.Error("Get(nope) = found, want not found")
	}
}

func TestRegistry_ReRegisterOverwrites(t *testing.T) {
	r := NewRegistry()
	r.Register("run-1", Info{SkillID: "old", Model: "opus"})
	r.Register("run-1", Info{SkillID: "new", Model: "sonnet"})

	got, ok := r.Get("run-1")
	if !ok || got.SkillID != "new" || got.Model != "sonnet" {
		t.Errorf("Get(run-1) = %+v, ok=%v, want {new sonnet}, true", got, ok)
	}
}

// TestRegistry_ConcurrentAccess proves the mutex actually guards the
// map — run with -race, which is what would catch a regression here.
func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		runID := "run-concurrent"
		go func() {
			defer wg.Done()
			r.Register(runID, Info{SkillID: "s"})
		}()
		go func() {
			defer wg.Done()
			r.Live(runID)
		}()
		go func() {
			defer wg.Done()
			r.Unregister(runID)
		}()
	}
	wg.Wait()
}
