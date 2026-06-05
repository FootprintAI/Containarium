package runner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBoxes implements BoxManager. Tracks calls so tests can
// assert on what the orchestrator did.
type fakeBoxes struct {
	mu       sync.Mutex
	existing map[string]bool // box name -> already present
	created  []string
	deleted  []string
	listOut  []string
	failCreate map[string]error
}

func (f *fakeBoxes) Exists(_ context.Context, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.existing[name], nil
}

func (f *fakeBoxes) Create(_ context.Context, name, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.failCreate[name]; ok {
		return "", err
	}
	f.created = append(f.created, name)
	f.existing[name] = true
	return name, nil
}

func (f *fakeBoxes) Delete(_ context.Context, name string, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, name)
	delete(f.existing, name)
	return nil
}

func (f *fakeBoxes) List(_ context.Context) ([]string, error) {
	return f.listOut, nil
}

// fakeInstaller implements RunnerInstaller. Records which boxes
// got an install call and lets tests pre-seed "already installed"
// status to exercise the idempotent path.
type fakeInstaller struct {
	mu             sync.Mutex
	alreadyInstalled map[string]bool
	installed      []string
	failInstall    map[string]error
	gotEnv         map[string]map[string]string
}

func (f *fakeInstaller) IsInstalled(_ context.Context, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.alreadyInstalled[name], nil
}

func (f *fakeInstaller) Install(_ context.Context, name string, _ []byte, env map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.failInstall[name]; ok {
		return err
	}
	f.installed = append(f.installed, name)
	if f.gotEnv == nil {
		f.gotEnv = make(map[string]map[string]string)
	}
	cp := make(map[string]string, len(env))
	for k, v := range env {
		cp[k] = v
	}
	f.gotEnv[name] = cp
	return nil
}

// fakeGitHub implements GitHubAPI. registerOnAttempt[name] = N
// means "ListRunners returns this name starting from the N-th
// call" — lets tests force the polling loop to spin a few times
// before success.
type fakeGitHub struct {
	mu                sync.Mutex
	listed            []string // names visible "now"
	listCalls         int
	registerOnAttempt map[string]int // name -> attempt index from which it becomes visible
	removed           []int64
	listErr           error
	removeErr         error
}

func (f *fakeGitHub) ListRunners(_ context.Context, _, _ string) ([]RegisteredRunner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	visible := append([]string(nil), f.listed...)
	for name, attempt := range f.registerOnAttempt {
		if f.listCalls >= attempt {
			visible = append(visible, name)
		}
	}
	out := make([]RegisteredRunner, 0, len(visible))
	for i, n := range visible {
		out = append(out, RegisteredRunner{ID: int64(i + 1), Name: n, Status: "online"})
	}
	return out, nil
}

func (f *fakeGitHub) RemoveRunner(_ context.Context, _, _ string, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removeErr != nil {
		return f.removeErr
	}
	f.removed = append(f.removed, id)
	return nil
}

// fakeClock advances on each Sleep so tests don't actually pause
// and the registration loop hits its deadline deterministically.
type fakeClock struct {
	now      time.Time
	sleeps   []time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_700_000_000, 0)}
}
func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Sleep(d time.Duration) {
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
}

// -----------------------------------------------------------------
// ValidateOptions
// -----------------------------------------------------------------

func TestValidateOptions(t *testing.T) {
	cases := []struct {
		name    string
		opts    Options
		wantErr string
	}{
		{
			name:    "empty repo",
			opts:    Options{Repo: "", PAT: "ghp_x", Count: 1},
			wantErr: "repo is required",
		},
		{
			name:    "bad repo format - no slash",
			opts:    Options{Repo: "owner-repo", PAT: "ghp_x", Count: 1},
			wantErr: "not in owner/repo format",
		},
		{
			name:    "bad repo format - leading slash",
			opts:    Options{Repo: "/repo", PAT: "ghp_x", Count: 1},
			wantErr: "not in owner/repo format",
		},
		{
			name:    "empty PAT",
			opts:    Options{Repo: "owner/repo", PAT: "", Count: 1},
			wantErr: "github_pat is required",
		},
		{
			name:    "count zero",
			opts:    Options{Repo: "owner/repo", PAT: "ghp_x", Count: 0},
			wantErr: "count must be > 0",
		},
		{
			name:    "count negative",
			opts:    Options{Repo: "owner/repo", PAT: "ghp_x", Count: -1},
			wantErr: "count must be > 0",
		},
		{
			name:    "count above cap",
			opts:    Options{Repo: "owner/repo", PAT: "ghp_x", Count: MaxRunnerCount + 1},
			wantErr: "exceeds maximum",
		},
		{
			name:    "valid",
			opts:    Options{Repo: "owner/repo", PAT: "ghp_x", Count: 3},
			wantErr: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOptions(tc.opts)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// -----------------------------------------------------------------
// RenderName
// -----------------------------------------------------------------

func TestRenderName(t *testing.T) {
	cases := []struct {
		template string
		prefix   string
		i        int
		want     string
	}{
		{"{prefix}-{i}", "ci-runner", 1, "ci-runner-1"},
		{"{prefix}-{i}", "ci-runner", 12, "ci-runner-12"},
		{"runner_{i}_{prefix}", "ci", 3, "runner_3_ci"},
		{"static", "anything", 9, "static"},
	}
	for _, tc := range cases {
		got := RenderName(tc.template, tc.prefix, tc.i)
		if got != tc.want {
			t.Errorf("RenderName(%q, %q, %d) = %q want %q",
				tc.template, tc.prefix, tc.i, got, tc.want)
		}
	}
}

// -----------------------------------------------------------------
// Provision — happy path, idempotent re-run, partial failure
// -----------------------------------------------------------------

func TestProvisionHappyPath(t *testing.T) {
	boxes := &fakeBoxes{existing: map[string]bool{}}
	installer := &fakeInstaller{alreadyInstalled: map[string]bool{}}
	gh := &fakeGitHub{}
	// All three runners become visible immediately on the first
	// ListRunners call (registerOnAttempt: attempt 1).
	gh.registerOnAttempt = map[string]int{
		"ci-runner-1": 1,
		"ci-runner-2": 1,
		"ci-runner-3": 1,
	}
	clock := newFakeClock()

	opts := Options{
		Repo:                "footprintai/containarium",
		PAT:                 "ghp_test",
		Count:               3,
		RegistrationTimeout: 30 * time.Second,
	}

	res, err := Provision(context.Background(), Deps{
		Boxes: boxes, SSH: installer, GitHub: gh, Clock: clock,
	}, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.PartialFailure {
		t.Fatalf("expected no partial failure, got %+v", res)
	}
	if len(res.Runners) != 3 {
		t.Fatalf("expected 3 runners, got %d", len(res.Runners))
	}
	for _, r := range res.Runners {
		if r.State != "provisioned" {
			t.Errorf("runner %s: expected state provisioned, got %s (err=%s)", r.Name, r.State, r.LastError)
		}
		if !r.Registered {
			t.Errorf("runner %s: expected Registered=true", r.Name)
		}
	}
	if len(boxes.created) != 3 {
		t.Errorf("expected 3 boxes created, got %d", len(boxes.created))
	}
	if len(installer.installed) != 3 {
		t.Errorf("expected 3 installs, got %d", len(installer.installed))
	}
	// Spot-check env propagation.
	if installer.gotEnv["ci-runner-2"]["GH_REPO"] != "footprintai/containarium" {
		t.Errorf("missing or wrong GH_REPO env: %+v", installer.gotEnv["ci-runner-2"])
	}
	if installer.gotEnv["ci-runner-2"]["RUNNER_NAME"] != "ci-runner-2" {
		t.Errorf("RUNNER_NAME mismatch: %+v", installer.gotEnv["ci-runner-2"])
	}
}

func TestProvisionIdempotent_BoxesAndServiceAlreadyExist(t *testing.T) {
	// Pre-seed: all three boxes exist AND the runner service
	// is already installed/enabled. Provision should skip both
	// the create and install steps, and report state=exists.
	boxes := &fakeBoxes{existing: map[string]bool{
		"ci-runner-1": true,
		"ci-runner-2": true,
		"ci-runner-3": true,
	}}
	installer := &fakeInstaller{alreadyInstalled: map[string]bool{
		"ci-runner-1": true,
		"ci-runner-2": true,
		"ci-runner-3": true,
	}}
	gh := &fakeGitHub{
		listed: []string{"ci-runner-1", "ci-runner-2", "ci-runner-3"},
	}
	clock := newFakeClock()

	opts := Options{
		Repo:                "footprintai/containarium",
		PAT:                 "ghp_test",
		Count:               3,
		RegistrationTimeout: 30 * time.Second,
	}

	res, err := Provision(context.Background(), Deps{
		Boxes: boxes, SSH: installer, GitHub: gh, Clock: clock,
	}, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.PartialFailure {
		t.Fatalf("idempotent path should not trip partial failure: %+v", res)
	}
	if len(boxes.created) != 0 {
		t.Errorf("expected zero creates (boxes already exist), got %d", len(boxes.created))
	}
	if len(installer.installed) != 0 {
		t.Errorf("expected zero installs (service already enabled), got %d", len(installer.installed))
	}
	for _, r := range res.Runners {
		if r.State != "exists" {
			t.Errorf("runner %s: expected state=exists, got %s", r.Name, r.State)
		}
		if !r.Registered {
			t.Errorf("runner %s: expected Registered=true", r.Name)
		}
	}
}

func TestProvisionPartialFailure(t *testing.T) {
	// Setup: box 2 fails to install. Boxes 1 and 3 succeed.
	// Result should carry both successes and the one failure,
	// with PartialFailure=true.
	boxes := &fakeBoxes{existing: map[string]bool{}}
	installer := &fakeInstaller{
		alreadyInstalled: map[string]bool{},
		failInstall: map[string]error{
			"ci-runner-2": errors.New("install script exited 1"),
		},
	}
	gh := &fakeGitHub{
		registerOnAttempt: map[string]int{
			"ci-runner-1": 1,
			"ci-runner-3": 1,
		},
	}
	clock := newFakeClock()

	opts := Options{
		Repo:                "footprintai/containarium",
		PAT:                 "ghp_test",
		Count:               3,
		RegistrationTimeout: 30 * time.Second,
	}

	res, err := Provision(context.Background(), Deps{
		Boxes: boxes, SSH: installer, GitHub: gh, Clock: clock,
	}, opts)
	if err != nil {
		t.Fatalf("unexpected error (partial failures shouldn't bubble as Go errors): %v", err)
	}
	if !res.PartialFailure {
		t.Fatalf("expected partial failure, got %+v", res)
	}

	byName := map[string]RunnerStatus{}
	for _, r := range res.Runners {
		byName[r.Name] = r
	}
	if byName["ci-runner-1"].State != "provisioned" {
		t.Errorf("runner 1: expected provisioned, got %s", byName["ci-runner-1"].State)
	}
	if byName["ci-runner-3"].State != "provisioned" {
		t.Errorf("runner 3: expected provisioned, got %s", byName["ci-runner-3"].State)
	}
	if byName["ci-runner-2"].State != "failed" {
		t.Errorf("runner 2: expected failed, got %s", byName["ci-runner-2"].State)
	}
	if !strings.Contains(byName["ci-runner-2"].LastError, "install script exited 1") {
		t.Errorf("runner 2: expected propagated install error in LastError, got %q",
			byName["ci-runner-2"].LastError)
	}
}

func TestProvisionRegistrationTimeout(t *testing.T) {
	// Box install succeeds, but GitHub never sees the runner.
	// State should be "registering" (transient), Registered=false,
	// PartialFailure stays false (registering isn't a hard fail).
	boxes := &fakeBoxes{existing: map[string]bool{}}
	installer := &fakeInstaller{alreadyInstalled: map[string]bool{}}
	gh := &fakeGitHub{
		// No runners ever become visible.
		registerOnAttempt: map[string]int{},
	}
	clock := newFakeClock()

	opts := Options{
		Repo:                "footprintai/containarium",
		PAT:                 "ghp_test",
		Count:               1,
		RegistrationTimeout: 5 * time.Second,
	}

	res, err := Provision(context.Background(), Deps{
		Boxes: boxes, SSH: installer, GitHub: gh, Clock: clock,
	}, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Runners) != 1 {
		t.Fatalf("expected 1 runner, got %d", len(res.Runners))
	}
	r := res.Runners[0]
	if r.State != "registering" {
		t.Errorf("expected state=registering, got %s (err=%s)", r.State, r.LastError)
	}
	if r.Registered {
		t.Errorf("expected Registered=false")
	}
	if res.PartialFailure {
		t.Errorf("registering is transient, should not flip PartialFailure")
	}
	// We should have made at least one poll attempt.
	if gh.listCalls == 0 {
		t.Errorf("expected at least one ListRunners call, got 0")
	}
}

func TestProvisionRegistrationPollSucceedsLater(t *testing.T) {
	// Runner shows up on the 3rd ListRunners call. Verify the
	// polling loop spins, backs off, and ultimately succeeds.
	boxes := &fakeBoxes{existing: map[string]bool{}}
	installer := &fakeInstaller{alreadyInstalled: map[string]bool{}}
	gh := &fakeGitHub{
		registerOnAttempt: map[string]int{"ci-runner-1": 3},
	}
	clock := newFakeClock()

	opts := Options{
		Repo:                "footprintai/containarium",
		PAT:                 "ghp_test",
		Count:               1,
		RegistrationTimeout: 60 * time.Second,
	}

	res, err := Provision(context.Background(), Deps{
		Boxes: boxes, SSH: installer, GitHub: gh, Clock: clock,
	}, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Runners[0].State != "provisioned" {
		t.Errorf("expected state=provisioned, got %s", res.Runners[0].State)
	}
	if gh.listCalls < 3 {
		t.Errorf("expected >=3 ListRunners calls, got %d", gh.listCalls)
	}
	// Sleep durations should follow the exponential backoff
	// pattern (2s, 4s, …).
	if len(clock.sleeps) < 2 {
		t.Errorf("expected at least 2 sleeps for backoff, got %d", len(clock.sleeps))
	}
	if clock.sleeps[0] != 2*time.Second {
		t.Errorf("first sleep should be 2s (backoff start), got %v", clock.sleeps[0])
	}
}

func TestProvisionBoxCreateFailureMarksFailed(t *testing.T) {
	boxes := &fakeBoxes{
		existing:   map[string]bool{},
		failCreate: map[string]error{"ci-runner-1": errors.New("incus refused")},
	}
	installer := &fakeInstaller{alreadyInstalled: map[string]bool{}}
	gh := &fakeGitHub{}
	clock := newFakeClock()

	opts := Options{
		Repo:                "footprintai/containarium",
		PAT:                 "ghp_test",
		Count:               1,
		RegistrationTimeout: 1 * time.Second,
	}

	res, err := Provision(context.Background(), Deps{
		Boxes: boxes, SSH: installer, GitHub: gh, Clock: clock,
	}, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.PartialFailure {
		t.Fatalf("expected partial failure")
	}
	if res.Runners[0].State != "failed" {
		t.Errorf("expected state=failed, got %s", res.Runners[0].State)
	}
	if !strings.Contains(res.Runners[0].LastError, "incus refused") {
		t.Errorf("expected propagated create error, got %q", res.Runners[0].LastError)
	}
	if len(installer.installed) != 0 {
		t.Errorf("install should not run when create fails")
	}
}

// -----------------------------------------------------------------
// List
// -----------------------------------------------------------------

func TestList_FilterByPrefixAndMergeGitHubState(t *testing.T) {
	boxes := &fakeBoxes{
		// Daemon has a mix of runner boxes and non-runner boxes.
		listOut: []string{"ci-runner-1", "ci-runner-2", "alice", "bob"},
	}
	gh := &fakeGitHub{
		listed: []string{"ci-runner-1"}, // only #1 is registered
	}

	res, err := List(context.Background(), Deps{Boxes: boxes, GitHub: gh}, Options{
		Repo: "owner/repo", PAT: "ghp_test", NamePrefix: "ci-runner",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Runners) != 2 {
		t.Fatalf("expected 2 runner boxes after prefix filter, got %d", len(res.Runners))
	}
	byName := map[string]RunnerStatus{}
	for _, r := range res.Runners {
		byName[r.Name] = r
	}
	if !byName["ci-runner-1"].Registered {
		t.Errorf("runner-1 should be registered")
	}
	if byName["ci-runner-2"].Registered {
		t.Errorf("runner-2 should NOT be registered")
	}
	if byName["ci-runner-2"].State != "unregistered" {
		t.Errorf("runner-2: expected state=unregistered, got %s", byName["ci-runner-2"].State)
	}
}

func TestList_RequiresRepoAndPAT(t *testing.T) {
	_, err := List(context.Background(), Deps{}, Options{Repo: "", PAT: "x"})
	if err == nil || !strings.Contains(err.Error(), "repo is required") {
		t.Errorf("expected repo-required error, got %v", err)
	}
	_, err = List(context.Background(), Deps{}, Options{Repo: "owner/repo", PAT: ""})
	if err == nil || !strings.Contains(err.Error(), "github_pat is required") {
		t.Errorf("expected pat-required error, got %v", err)
	}
}

// -----------------------------------------------------------------
// Remove
// -----------------------------------------------------------------

func TestRemove_DeregistersAndDeletes(t *testing.T) {
	boxes := &fakeBoxes{existing: map[string]bool{"ci-runner-1": true}}
	gh := &fakeGitHub{listed: []string{"ci-runner-1"}}

	st, err := Remove(context.Background(), Deps{Boxes: boxes, GitHub: gh}, Options{
		Repo: "owner/repo", PAT: "ghp_test",
	}, "ci-runner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.State != "removed" {
		t.Errorf("expected state=removed, got %s", st.State)
	}
	if len(gh.removed) != 1 {
		t.Errorf("expected 1 github removal, got %d", len(gh.removed))
	}
	if len(boxes.deleted) != 1 || boxes.deleted[0] != "ci-runner-1" {
		t.Errorf("expected box delete of ci-runner-1, got %v", boxes.deleted)
	}
}

func TestRemove_GitHubFailureDoesNotBlockBoxDelete(t *testing.T) {
	boxes := &fakeBoxes{existing: map[string]bool{"ci-runner-1": true}}
	gh := &fakeGitHub{
		listed:  []string{"ci-runner-1"},
		removeErr: errors.New("github 500"),
	}

	st, err := Remove(context.Background(), Deps{Boxes: boxes, GitHub: gh}, Options{
		Repo: "owner/repo", PAT: "ghp_test",
	}, "ci-runner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.State != "removed" {
		t.Errorf("expected state=removed, got %s (err=%s)", st.State, st.LastError)
	}
	if !strings.Contains(st.LastError, "github 500") {
		t.Errorf("expected propagated github error in LastError, got %q", st.LastError)
	}
	if len(boxes.deleted) != 1 {
		t.Errorf("expected box delete to proceed despite github failure")
	}
}

func TestRemove_RejectsMissingArgs(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		box  string
		want string
	}{
		{"no name", Options{Repo: "owner/repo", PAT: "x"}, "", "name is required"},
		{"no repo", Options{Repo: "", PAT: "x"}, "n", "repo and github_pat are required"},
		{"no pat", Options{Repo: "owner/repo", PAT: ""}, "n", "repo and github_pat are required"},
		{"bad repo", Options{Repo: "garbage", PAT: "x"}, "n", "not in owner/repo format"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Remove(context.Background(), Deps{}, tc.opts, tc.box)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// -----------------------------------------------------------------
// Embedded install script lockstep with hacks/runner/install.sh
// -----------------------------------------------------------------

// TestEmbeddedInstallScriptNonEmpty makes sure go:embed actually
// picked up the script. Without this, a missing copy of install.sh
// would silently ship an empty payload to the runner box.
func TestEmbeddedInstallScriptNonEmpty(t *testing.T) {
	if len(InstallScript) == 0 {
		t.Fatal("InstallScript is empty — go:embed didn't pick up install_script_payload.sh")
	}
	if !strings.Contains(string(InstallScript), "GH_REPO") {
		t.Errorf("embedded script doesn't mention GH_REPO — likely wrong file embedded")
	}
}

// -----------------------------------------------------------------
// Defaults are applied
// -----------------------------------------------------------------

func TestApplyDefaults(t *testing.T) {
	// Force the cap to its built-in default regardless of the ambient
	// environment so MaxTotal is deterministic.
	t.Setenv("MAX_RUNNERS_TOTAL", "")
	got := applyDefaults(Options{Repo: "owner/repo", PAT: "x", Count: 1})
	want := Options{
		Repo:                "owner/repo",
		PAT:                 "x",
		Count:               1,
		NamePrefix:          "ci-runner",
		Labels:              "containarium,ephemeral",
		NameTemplate:        "{prefix}-{i}",
		BoxCreateTimeout:    DefaultBoxCreateTimeout,
		InstallTimeout:      DefaultInstallTimeout,
		RegistrationTimeout: DefaultRegistrationTimeout,
		MaxTotal:            DefaultMaxRunnersTotal,
	}
	if got != want {
		t.Errorf("applyDefaults mismatch:\n  got:  %+v\n  want: %+v", got, want)
	}
}

// Compile-time check: our fakes satisfy the interfaces. This catches
// a method-signature drift before tests run.
var (
	_ BoxManager      = (*fakeBoxes)(nil)
	_ RunnerInstaller = (*fakeInstaller)(nil)
	_ GitHubAPI       = (*fakeGitHub)(nil)
	_ Clock           = (*fakeClock)(nil)
)

// Suppress unused-import warnings if a future refactor drops fmt
// inside this file.
var _ = fmt.Sprintf
