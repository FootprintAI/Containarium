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

// TestRegistry_InfoCarriesBoxGitCommitWorkspace is #1923's addition:
// SubmitTrackerChange needs to resolve a run's box, base commit,
// workspace path, and original ref from the same registry
// ClaimTrackerIssue already reads for liveness — a round trip through
// Register/Get must carry all four through unchanged, including the
// case where a run had no git_source at all (empty
// GitCommit/Workspace/GitRef, not a zero-value that looks like a
// mistake).
func TestRegistry_InfoCarriesBoxGitCommitWorkspace(t *testing.T) {
	r := NewRegistry()
	r.Register("run-1", Info{
		SkillID:   "code-review",
		Model:     "sonnet",
		Box:       "agent-code-review",
		GitCommit: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		Workspace: "/workspace/runs/run-1",
		GitRef:    "main",
	})

	got, ok := r.Get("run-1")
	if !ok {
		t.Fatal("Get(run-1) = not found, want found")
	}
	want := Info{
		SkillID:   "code-review",
		Model:     "sonnet",
		Box:       "agent-code-review",
		GitCommit: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		Workspace: "/workspace/runs/run-1",
		GitRef:    "main",
	}
	if got != want {
		t.Errorf("Get(run-1) = %+v, want %+v", got, want)
	}
}

func TestRegistry_InfoWithNoGitSourceLeavesCommitAndWorkspaceEmpty(t *testing.T) {
	r := NewRegistry()
	r.Register("run-2", Info{SkillID: "no-git-skill", Box: "agent-no-git-skill"})

	got, ok := r.Get("run-2")
	if !ok {
		t.Fatal("Get(run-2) = not found, want found")
	}
	if got.GitCommit != "" || got.Workspace != "" || got.GitRef != "" {
		t.Errorf("Get(run-2) = %+v, want empty GitCommit/Workspace/GitRef for a run with no git_source", got)
	}
	if got.Box != "agent-no-git-skill" {
		t.Errorf("Get(run-2).Box = %q, want agent-no-git-skill", got.Box)
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
