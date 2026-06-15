package capacity

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// fakeStopper records every StopWorkload call and lets a test script per-call
// behavior (error once, error always) so the drainer's graceful→force fallback
// and failure recording are observable.
type fakeStopper struct {
	mu    sync.Mutex
	calls []stopCall
	// failGraceful: usernames whose non-forced stop returns an error (the
	// drainer should then retry with force).
	failGraceful map[string]bool
	// failAll: usernames whose stop always errors (records into Failed).
	failAll map[string]bool
}

type stopCall struct {
	username string
	force    bool
}

func (f *fakeStopper) StopWorkload(_ context.Context, username string, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, stopCall{username: username, force: force})
	if f.failAll[username] {
		return errors.New("boom")
	}
	if !force && f.failGraceful[username] {
		return errors.New("graceful refused")
	}
	return nil
}

func (f *fakeStopper) callsFor(username string) []stopCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []stopCall
	for _, c := range f.calls {
		if c.username == username {
			out = append(out, c)
		}
	}
	return out
}

func cand(name, user string) DrainCandidate {
	return DrainCandidate{ContainerName: name, Username: user}
}

func TestDrainAllGraceful(t *testing.T) {
	fs := &fakeStopper{}
	d := NewDrainer(fs)
	res, skipped := d.Drain(context.Background(),
		[]DrainCandidate{cand("a-container", "a"), cand("b-container", "b")},
		time.Minute)
	if skipped {
		t.Fatal("unexpected skip on first drain")
	}
	if len(res.Drained) != 2 {
		t.Fatalf("Drained = %v, want 2", res.Drained)
	}
	if res.WindowExceeded {
		t.Fatal("WindowExceeded should be false when nothing forced")
	}
	if len(res.ForceStopped) != 0 || len(res.Failed) != 0 {
		t.Fatalf("expected no force/fail, got force=%v fail=%v", res.ForceStopped, res.Failed)
	}
	// Each was stopped exactly once, gracefully (force=false).
	for _, u := range []string{"a", "b"} {
		c := fs.callsFor(u)
		if len(c) != 1 || c[0].force {
			t.Fatalf("user %s calls = %+v, want one graceful stop", u, c)
		}
	}
}

func TestDrainGracefulRefusedFallsBackToForce(t *testing.T) {
	fs := &fakeStopper{failGraceful: map[string]bool{"a": true}}
	d := NewDrainer(fs)
	res, _ := d.Drain(context.Background(),
		[]DrainCandidate{cand("a-container", "a")}, time.Minute)

	if len(res.ForceStopped) != 1 || res.ForceStopped[0] != "a-container" {
		t.Fatalf("ForceStopped = %v, want [a-container]", res.ForceStopped)
	}
	if len(res.Failed) != 0 {
		t.Fatalf("Failed = %v, want empty", res.Failed)
	}
	// First graceful (errored) then a forced retry.
	c := fs.callsFor("a")
	if len(c) != 2 || c[0].force || !c[1].force {
		t.Fatalf("calls = %+v, want graceful then forced", c)
	}
}

func TestDrainRecordsFailure(t *testing.T) {
	fs := &fakeStopper{failAll: map[string]bool{"a": true}}
	d := NewDrainer(fs)
	res, _ := d.Drain(context.Background(),
		[]DrainCandidate{cand("a-container", "a"), cand("b-container", "b")}, time.Minute)

	if _, ok := res.Failed["a-container"]; !ok {
		t.Fatalf("Failed should record a-container, got %v", res.Failed)
	}
	// A stuck guest must not block reclaiming the rest.
	if len(res.Drained) != 1 || res.Drained[0] != "b-container" {
		t.Fatalf("Drained = %v, want [b-container] (b still reclaimed)", res.Drained)
	}
}

// TestDrainWindowExceededForcesRemainder pins the clock so the deadline is
// already in the past on the second candidate; that candidate must be
// force-stopped and WindowExceeded set.
func TestDrainWindowExceededForcesRemainder(t *testing.T) {
	fs := &fakeStopper{}
	d := NewDrainer(fs)

	base := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	// now() is called: start, then once per candidate for the deadline check,
	// then once at the end for Elapsed. Window is 10s. Advance the clock past
	// the deadline before the second candidate's check.
	ticks := []time.Time{
		base,                       // start
		base.Add(1 * time.Second),  // candidate a: within window
		base.Add(30 * time.Second), // candidate b: past 10s window
		base.Add(31 * time.Second), // elapsed
	}
	i := 0
	d.nowFn = func() time.Time {
		t := ticks[i]
		if i < len(ticks)-1 {
			i++
		}
		return t
	}

	res, _ := d.Drain(context.Background(),
		[]DrainCandidate{cand("a-container", "a"), cand("b-container", "b")},
		10*time.Second)

	if !res.WindowExceeded {
		t.Fatal("WindowExceeded should be true")
	}
	if len(res.Drained) != 1 || res.Drained[0] != "a-container" {
		t.Fatalf("Drained = %v, want [a-container]", res.Drained)
	}
	if len(res.ForceStopped) != 1 || res.ForceStopped[0] != "b-container" {
		t.Fatalf("ForceStopped = %v, want [b-container]", res.ForceStopped)
	}
	// b was force-stopped (no graceful attempt once past the window).
	c := fs.callsFor("b")
	if len(c) != 1 || !c[0].force {
		t.Fatalf("b calls = %+v, want single forced stop", c)
	}
}

// TestDrainCoalescesConcurrent verifies the in-flight guard: a second drain
// arriving while the first holds the lock is skipped (returns skipped=true,
// zero result, no stops) — repeated withdraw cycles can't stack stop storms.
func TestDrainCoalescesConcurrent(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	bs := &blockingStopper{entered: entered, release: release}
	d := NewDrainer(bs)

	var firstRes DrainResult
	var firstSkipped bool
	done := make(chan struct{})
	go func() {
		firstRes, firstSkipped = d.Drain(context.Background(),
			[]DrainCandidate{cand("a-container", "a")}, time.Minute)
		close(done)
	}()

	<-entered // first drain is now inside StopWorkload, holding the guard
	res2, skipped2 := d.Drain(context.Background(),
		[]DrainCandidate{cand("b-container", "b")}, time.Minute)
	if !skipped2 {
		t.Fatal("second concurrent drain should be coalesced (skipped)")
	}
	if len(res2.Drained) != 0 || len(res2.ForceStopped) != 0 {
		t.Fatalf("skipped drain must return zero result, got %+v", res2)
	}

	close(release)
	<-done
	if firstSkipped {
		t.Fatal("first drain should not be skipped")
	}
	if len(firstRes.Drained) != 1 {
		t.Fatalf("first drain Drained = %v, want 1", firstRes.Drained)
	}
}

// blockingStopper blocks inside the first StopWorkload until released, so the
// test can race a second Drain against the in-flight guard deterministically.
type blockingStopper struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (b *blockingStopper) StopWorkload(_ context.Context, _ string, _ bool) error {
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return nil
}

func TestDrainWindowDefaults(t *testing.T) {
	fs := &fakeStopper{}
	d := NewDrainer(fs)
	// window <= 0 falls back to DefaultDrainWindow; with a graceful stopper the
	// drain completes well inside it.
	res, _ := d.Drain(context.Background(), []DrainCandidate{cand("a-container", "a")}, 0)
	if res.WindowExceeded {
		t.Fatal("default window should not be exceeded for an instant stop")
	}
	if len(res.Drained) != 1 {
		t.Fatalf("Drained = %v, want 1", res.Drained)
	}
}

func TestDrainCandidatesFiltersAndMapsUsername(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour) // idle past the default 15m threshold
	st := HostState{
		Now: now,
		Containers: []incus.ContainerInfo{
			{Name: "guest-container", Username: "guest", State: "Running", LastStartedAt: old},
			{Name: "stopped-container", Username: "stopped", State: "Stopped", LastStartedAt: old},
			{Name: "core", State: "Running", Role: incus.RolePostgres, LastStartedAt: old},
			{
				Name:          "protected-container",
				State:         "Running",
				Labels:        map[string]string{WorkloadClassLabel: "critical"},
				LastStartedAt: old,
			},
			// Running but only just started → still busy, not part of the idle
			// spare the backend offered → must NOT be drained.
			{Name: "busy-container", Username: "busy", State: "Running", LastStartedAt: now},
			// No Username reported: candidate falls back to the name.
			{Name: "noname-container", State: "Running", LastStartedAt: old},
		},
	}
	p := Policy{ExcludedWorkloadClasses: []string{"critical"}}
	got := DrainCandidates(p, st)

	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2: %+v", len(got), got)
	}
	byName := map[string]DrainCandidate{}
	for _, c := range got {
		byName[c.ContainerName] = c
	}
	if c, ok := byName["guest-container"]; !ok || c.Username != "guest" {
		t.Fatalf("guest candidate = %+v, want username guest", c)
	}
	if c, ok := byName["noname-container"]; !ok || c.Username != "noname-container" {
		t.Fatalf("noname candidate = %+v, want username fallback to name", c)
	}
	if _, ok := byName["busy-container"]; ok {
		t.Fatalf("busy (non-idle) container must not be a drain candidate")
	}
}
