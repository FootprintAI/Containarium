package container

import (
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// stagesBackend fakes exactly what Create touches on the baked-image path.
// It embeds incus.Backend (nil) for the rest of the interface, so a call to
// anything unimplemented panics and names the gap.
type stagesBackend struct {
	incus.Backend
	waitNetworkErr error
	onWaitNetwork  func() // called on entry to WaitForNetwork, when set
	deleteCalls    int    // DeleteContainer invocations (cleanup evidence)
}

func (b *stagesBackend) GetImageAliasProperties(string) (map[string]string, bool, error) {
	// A baked image matching Create's default image + podman=false, so the
	// test skips installPackages (which sleeps 5s waiting for cloud-init).
	return map[string]string{
		bakedPropBaked:  "true",
		bakedPropSource: "images:ubuntu/24.04",
		bakedPropPodman: strconv.FormatBool(false),
	}, true, nil
}

func (b *stagesBackend) CreateContainer(incus.ContainerConfig) error { return nil }
func (b *stagesBackend) StartContainer(string) error                 { return nil }
func (b *stagesBackend) StopContainer(string, bool) error            { return nil }
func (b *stagesBackend) DeleteContainer(string) error                { b.deleteCalls++; return nil }
func (b *stagesBackend) SetLabels(string, map[string]string) error   { return nil }
func (b *stagesBackend) Exec(string, []string) error                 { return nil }
func (b *stagesBackend) WriteFile(string, string, []byte, string) error {
	return nil
}

func (b *stagesBackend) WaitForNetwork(string, time.Duration) (string, error) {
	if b.onWaitNetwork != nil {
		b.onWaitNetwork()
	}
	if b.waitNetworkErr != nil {
		return "", b.waitNetworkErr
	}
	return "203.0.113.7", nil
}

func (b *stagesBackend) GetContainer(name string) (*incus.ContainerInfo, error) {
	return &incus.ContainerInfo{Name: name}, nil
}

// stageLog records every observation in order. Mutex-guarded because the
// jump-account stage reports from its own goroutine.
type stageLog struct {
	mu        sync.Mutex
	stages    []CreateStage
	durations map[CreateStage]time.Duration
}

func newStageLog() *stageLog {
	return &stageLog{durations: make(map[CreateStage]time.Duration)}
}

func (l *stageLog) observer() StageObserver {
	return func(s CreateStage, d time.Duration) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.stages = append(l.stages, s)
		l.durations[s] = d
	}
}

func stagesOpts() CreateOptions {
	return CreateOptions{
		Username: "alice",
		Image:    "images:ubuntu/24.04",
		// No SSHKeys: the jump-account stage runs host useradd, which a unit
		// test must not touch. Its absence is asserted below.
	}
}

// TestCreate_ObservesStagesInOrder pins the Phase 0 instrumentation contract
// (docs/architecture/two-digit-ms-sandbox-spawn.md): every stage that runs is
// observed, in execution order, and stages that are skipped — baked image,
// no SSH keys, no git source — produce no observation at all.
func TestCreate_ObservesStagesInOrder(t *testing.T) {
	// Keep getJumpServerSSHKey from finding a real key in $HOME, which would
	// nondeterministically add an add_ssh_keys stage on developer machines.
	t.Setenv("HOME", t.TempDir())

	log := newStageLog()
	m := NewWithBackend(&stagesBackend{})
	m.SetStageObserver(log.observer())

	if _, err := m.Create(stagesOpts()); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Every stage this create actually runs, in path order. add_ssh_keys is
	// excluded: it depends on whether the host has a jump-server key, which
	// the HOME override above pins to "no".
	want := []CreateStage{
		StageCreateInstance,
		StageStartInstance,
		StageSetLabels,
		StageWaitNetwork,
		StageCreateUser,
		StageGetInfo,
		StageTotal,
	}
	assertSubsequence(t, log.stages, want)

	for _, absent := range []CreateStage{StageJumpAccount, StageInstallPackages, StageGitSource, StageAddSSHKeys} {
		if _, ok := log.durations[absent]; ok {
			t.Errorf("stage %q was observed but should have been skipped (observed: %v)", absent, log.stages)
		}
	}

	for stage, d := range log.durations {
		if d < 0 {
			t.Errorf("stage %q recorded negative duration %v", stage, d)
		}
	}
	if log.durations[StageTotal] < log.durations[StageStartInstance] {
		t.Errorf("total (%v) must cover start_instance (%v)", log.durations[StageTotal], log.durations[StageStartInstance])
	}
}

// TestCreate_NilObserverIsNoop — the default: no observer, no panic, same
// create.
func TestCreate_NilObserverIsNoop(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	m := NewWithBackend(&stagesBackend{})
	if _, err := m.Create(stagesOpts()); err != nil {
		t.Fatalf("Create without observer: %v", err)
	}
}

// TestCreate_FailedStageIsStillObserved pins the documented semantics: a
// stage that errors is still recorded (its duration is real — a network wait
// that burns its timeout is exactly the sample worth keeping), while total is
// recorded only on success.
func TestCreate_FailedStageIsStillObserved(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	log := newStageLog()
	m := NewWithBackend(&stagesBackend{waitNetworkErr: errors.New("no lease")})
	m.SetStageObserver(log.observer())

	if _, err := m.Create(stagesOpts()); err == nil {
		t.Fatal("Create should fail when WaitForNetwork fails")
	}

	if _, ok := log.durations[StageWaitNetwork]; !ok {
		t.Errorf("failed wait_network stage was not observed (observed: %v)", log.stages)
	}
	if _, ok := log.durations[StageTotal]; ok {
		t.Errorf("total must not be observed on a failed create (observed: %v)", log.stages)
	}
}

// assertSubsequence fails unless want appears in got in order (other
// elements may be interleaved).
func assertSubsequence(t *testing.T, got, want []CreateStage) {
	t.Helper()
	i := 0
	for _, s := range got {
		if i < len(want) && s == want[i] {
			i++
		}
	}
	if i != len(want) {
		t.Errorf("stage order mismatch: missing %q\n  got:  %v\n  want subsequence: %v", want[i], got, want)
	}
}
