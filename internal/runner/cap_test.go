package runner

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// -----------------------------------------------------------------
// MaxRunnersTotal env parsing
// -----------------------------------------------------------------

func TestMaxRunnersTotal(t *testing.T) {
	cases := []struct {
		name string
		env  string
		set  bool
		want int
	}{
		{"unset -> default", "", false, DefaultMaxRunnersTotal},
		{"empty -> default", "", true, DefaultMaxRunnersTotal},
		{"valid", "7", true, 7},
		{"whitespace", "  12 ", true, 12},
		{"garbage -> default", "abc", true, DefaultMaxRunnersTotal},
		{"zero -> default", "0", true, DefaultMaxRunnersTotal},
		{"negative -> default", "-5", true, DefaultMaxRunnersTotal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("MAX_RUNNERS_TOTAL", tc.env)
			} else {
				// Ensure no ambient value leaks in.
				t.Setenv("MAX_RUNNERS_TOTAL", "")
			}
			if got := MaxRunnersTotal(); got != tc.want {
				t.Errorf("MaxRunnersTotal() = %d, want %d", got, tc.want)
			}
		})
	}
}

// -----------------------------------------------------------------
// CountLiveRunners
// -----------------------------------------------------------------

func TestCountLiveRunners(t *testing.T) {
	boxes := &fakeBoxes{
		listOut: []string{"ci-runner-1", "ci-runner-2", "alice", "bob", "ci-runner-x"},
	}
	n, err := CountLiveRunners(context.Background(), Deps{Boxes: boxes}, "ci-runner")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 ci-runner* boxes, got %d", n)
	}

	// Empty prefix falls back to the default "ci-runner".
	n, err = CountLiveRunners(context.Background(), Deps{Boxes: boxes}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 3 {
		t.Errorf("default-prefix count expected 3, got %d", n)
	}
}

// -----------------------------------------------------------------
// Provision cap enforcement
// -----------------------------------------------------------------

// helper: build deps whose box listing reports `existing` live
// runner boxes (names that do NOT collide with the ones Provision
// will generate, so the requested runners are all net-new).
func capDeps(liveNames []string) (Deps, *fakeBoxes) {
	boxes := &fakeBoxes{existing: map[string]bool{}, listOut: liveNames}
	return Deps{
		Boxes:  boxes,
		SSH:    &fakeInstaller{alreadyInstalled: map[string]bool{}},
		GitHub: &fakeGitHub{registerOnAttempt: map[string]int{}},
		Clock:  newFakeClock(),
	}, boxes
}

func filledNames(prefix string, n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		// Names distinct from the generated "ci-runner-<i>" set so
		// requested runners are net-new (use a letter suffix).
		out = append(out, fmt.Sprintf("%s-x%d", prefix, i))
	}
	return out
}

func TestProvisionRespectsCap_ClampsToHeadroom(t *testing.T) {
	// 18 live runner boxes, cap 20 → headroom 2. Request 5 → 2
	// created, 3 deferred/queued.
	deps, boxes := capDeps(filledNames("ci-runner", 18))
	opts := Options{
		Repo:                "owner/repo",
		PAT:                 "ghp_x",
		Count:               5,
		MaxTotal:            20,
		RegistrationTimeout: 1 * time.Second,
	}
	res, err := Provision(context.Background(), deps, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Deferred != 3 {
		t.Errorf("expected Deferred=3, got %d", res.Deferred)
	}
	if res.PartialFailure {
		t.Errorf("deferral is backpressure, must not set PartialFailure")
	}
	if len(boxes.created) != 2 {
		t.Errorf("expected exactly 2 boxes created (headroom), got %d (%v)", len(boxes.created), boxes.created)
	}
	queued := 0
	for _, r := range res.Runners {
		if r.State == "queued" {
			queued++
		}
	}
	if queued != 3 {
		t.Errorf("expected 3 queued rows, got %d", queued)
	}
}

func TestProvisionAtCap_DefersAllNotError(t *testing.T) {
	// Already at the ceiling → zero creates, all requested deferred,
	// no Go error, no PartialFailure.
	deps, boxes := capDeps(filledNames("ci-runner", 20))
	opts := Options{
		Repo:                "owner/repo",
		PAT:                 "ghp_x",
		Count:               3,
		MaxTotal:            20,
		RegistrationTimeout: 1 * time.Second,
	}
	res, err := Provision(context.Background(), deps, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(boxes.created) != 0 {
		t.Errorf("expected zero creates at cap, got %d", len(boxes.created))
	}
	if res.Deferred != 3 {
		t.Errorf("expected Deferred=3, got %d", res.Deferred)
	}
	if res.PartialFailure {
		t.Errorf("at-cap is not a failure")
	}
	for _, r := range res.Runners {
		if r.State != "queued" {
			t.Errorf("expected all rows queued, got %s for %s", r.State, r.Name)
		}
	}
}

func TestProvisionCapIgnoresNonPrefixBoxes(t *testing.T) {
	// 19 non-runner boxes + 1 runner box, cap 20. Only the single
	// ci-runner* box counts → headroom 19. Request 3 → all created.
	live := append([]string{"ci-runner-x0"}, filledNamesPlain("tenant", 19)...)
	deps, boxes := capDeps(live)
	opts := Options{
		Repo:                "owner/repo",
		PAT:                 "ghp_x",
		Count:               3,
		MaxTotal:            20,
		RegistrationTimeout: 1 * time.Second,
	}
	res, err := Provision(context.Background(), deps, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Deferred != 0 {
		t.Errorf("non-runner boxes must not consume headroom; Deferred=%d", res.Deferred)
	}
	if len(boxes.created) != 3 {
		t.Errorf("expected 3 creates, got %d", len(boxes.created))
	}
}

func filledNamesPlain(prefix string, n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%s-%d", prefix, i))
	}
	return out
}

func TestProvisionCapDefaultsFromEnv(t *testing.T) {
	// With MaxTotal unset on Options, applyDefaults pulls the env.
	t.Setenv("MAX_RUNNERS_TOTAL", "1")
	deps, boxes := capDeps(nil)
	opts := Options{
		Repo:                "owner/repo",
		PAT:                 "ghp_x",
		Count:               3, // env cap of 1 → only 1 created
		RegistrationTimeout: 1 * time.Second,
	}
	res, err := Provision(context.Background(), deps, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(boxes.created) != 1 {
		t.Errorf("expected 1 create under env cap of 1, got %d", len(boxes.created))
	}
	if res.Deferred != 2 {
		t.Errorf("expected Deferred=2, got %d", res.Deferred)
	}
}
