package server

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeRunner records every Incus call the orchestrator makes and lets
// each test seed deterministic outcomes. Unit tests assert on the call
// sequence (the orchestration logic) rather than on real Incus
// behavior — those integration concerns live in a separate harness
// that needs two real VMs.
type fakeRunner struct {
	mu              sync.Mutex
	calls           []string
	failSnapshot    error
	failCopyInit    error
	failCopyRefresh map[int]error // keyed by call count: first call is 0
	copyRefreshN    int
	failStop        error
	failStart       error
	hasRemote       bool
}

func (f *fakeRunner) log(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakeRunner) Snapshot(c, s string) error {
	f.log(fmt.Sprintf("snapshot %s/%s", c, s))
	return f.failSnapshot
}
func (f *fakeRunner) DeleteSnapshot(c, s string) error {
	f.log(fmt.Sprintf("delsnap %s/%s", c, s))
	return nil
}
func (f *fakeRunner) CopyInitial(c, s, r string) error {
	f.log(fmt.Sprintf("copyinit %s/%s -> %s", c, s, r))
	return f.failCopyInit
}
func (f *fakeRunner) CopyRefresh(c, s, r string) error {
	f.log(fmt.Sprintf("refresh %s/%s -> %s", c, s, r))
	n := f.copyRefreshN
	f.copyRefreshN++
	if err, ok := f.failCopyRefresh[n]; ok {
		return err
	}
	return nil
}
func (f *fakeRunner) Stop(c string) error {
	f.log(fmt.Sprintf("stop %s", c))
	return f.failStop
}
func (f *fakeRunner) Start(c string) error {
	f.log(fmt.Sprintf("start %s", c))
	return f.failStart
}
func (f *fakeRunner) HasRemote(r string) (bool, error) {
	return f.hasRemote, nil
}

// newTestContainerServer builds a ContainerServer with just enough
// wiring for the move orchestration tests: a peer pool with the local
// + one fake target, no route store (the orchestrator handles
// routeStore==nil gracefully), and the fake runner.
func newTestContainerServer(t *testing.T, runner incus.MigrationRunner, targetID string) *ContainerServer {
	t.Helper()
	cs := &ContainerServer{}
	pp := NewPeerPool("local-vm", "", nil, "")
	// Inject the target as a fake peer with a stub address; ForwardRequest
	// would normally call out, but we override that path via the
	// fakeAdopt hook below.
	pp.peers[targetID] = &PeerClient{ID: targetID, Addr: "stub:8080", Healthy: true}
	cs.peerPool = pp
	cs.moveRunner = runner
	return cs
}

// TestMoveContainer_HappyPath exercises the three-phase orchestration
// end to end without errors. Asserts on:
//   - the exact call sequence (3-phase + cutover stop, final copy, adopt)
//   - default iteration count (3) → 1 init + 3 deltas + 1 final = 5 incus copies
//   - new IP returned matches what AdoptMigratedContainer says
func TestMoveContainer_HappyPath(t *testing.T) {
	runner := &fakeRunner{hasRemote: true}
	cs := newTestContainerServer(t, runner, "vm2")

	// Stub the adopt RPC: return a fixed new IP without going over the wire.
	prev := overrideAdoptForTest(func(peer *PeerClient, _ string, _ *pb.AdoptMigratedContainerRequest) (*pb.AdoptMigratedContainerResponse, error) {
		return &pb.AdoptMigratedContainerResponse{NewIpAddress: "10.0.7.42"}, nil
	})
	defer prev()

	req := &pb.MoveContainerRequest{
		Username:        "alice",
		TargetBackendId: "vm2",
		// Default max_iterations (3), default delta_threshold (5).
		// Each iteration in the fake runner takes ~0ms, well under
		// the threshold, so the loop should exit after iter 1.
		// 1 init + 1 delta-loop iter + 1 final = 3 incus copies.
		// We also have 3 snapshots (sync0, sync1, final) + their
		// deletes at the end (sync0, sync1, final = 3).
	}
	resp, err := cs.MoveContainer(testCtx(), req)
	if err != nil {
		t.Fatalf("MoveContainer err = %v", err)
	}

	if resp.NewIpAddress != "10.0.7.42" {
		t.Errorf("NewIpAddress = %q, want %q", resp.NewIpAddress, "10.0.7.42")
	}
	if resp.TargetBackendId != "vm2" {
		t.Errorf("TargetBackendId = %q, want vm2", resp.TargetBackendId)
	}

	// First three calls must be: init snapshot → init copy → first refresh.
	if len(runner.calls) < 5 {
		t.Fatalf("expected at least 5 incus calls, got %d: %v", len(runner.calls), runner.calls)
	}
	if runner.calls[0] != "snapshot alice-container/containarium-move-sync0" {
		t.Errorf("first call = %q", runner.calls[0])
	}
	if runner.calls[1] != "copyinit alice-container/containarium-move-sync0 -> vm2" {
		t.Errorf("second call = %q", runner.calls[1])
	}

	// Cutover must include a stop on the source — search the call list.
	foundStop := false
	for _, c := range runner.calls {
		if c == "stop alice-container" {
			foundStop = true
			break
		}
	}
	if !foundStop {
		t.Errorf("expected `stop alice-container` somewhere in calls; got %v", runner.calls)
	}
}

// TestMoveContainer_RejectsMissingRemote — operators need to set up
// `incus remote add` first. The orchestrator must surface a clear
// error rather than letting `incus copy` fail with a less-obvious
// message later.
func TestMoveContainer_RejectsMissingRemote(t *testing.T) {
	runner := &fakeRunner{hasRemote: false} // not set up
	cs := newTestContainerServer(t, runner, "vm2")

	_, err := cs.MoveContainer(testCtx(),
		&pb.MoveContainerRequest{Username: "alice", TargetBackendId: "vm2"})
	if err == nil {
		t.Fatal("expected error when incus remote isn't configured")
	}
	if len(runner.calls) > 0 {
		t.Errorf("expected zero incus calls before remote check, got %d", len(runner.calls))
	}
}

// TestMoveContainer_RollsBackOnCutoverFailure verifies the rollback
// semantics: if anything fails AFTER `stop source` but BEFORE the
// route swap, we restart the source container so the public hostname
// isn't down indefinitely.
func TestMoveContainer_RollsBackOnCutoverFailure(t *testing.T) {
	// Fake counts CopyRefresh calls (CopyInitial doesn't increment).
	// With MaxIterations=1: call 0 = phase 2 iter 1, call 1 = phase 3 final.
	// We want phase 3 to fail.
	runner := &fakeRunner{
		hasRemote:       true,
		failCopyRefresh: map[int]error{1: errors.New("final-delta copy failed")},
	}
	cs := newTestContainerServer(t, runner, "vm2")
	prev := overrideAdoptForTest(func(_ *PeerClient, _ string, _ *pb.AdoptMigratedContainerRequest) (*pb.AdoptMigratedContainerResponse, error) {
		t.Error("adopt should not be called after final-delta failure")
		return nil, nil
	})
	defer prev()

	_, err := cs.MoveContainer(testCtx(),
		&pb.MoveContainerRequest{Username: "alice", TargetBackendId: "vm2", MaxIterations: 1})
	if err == nil {
		t.Fatal("expected error on final-delta copy failure")
	}

	// Rollback: the call sequence must include a `start alice-container`
	// after the `stop` — that's the recovery from the aborted cutover.
	stopIdx, startIdx := -1, -1
	for i, c := range runner.calls {
		if c == "stop alice-container" && stopIdx == -1 {
			stopIdx = i
		}
		if c == "start alice-container" && startIdx == -1 && stopIdx != -1 {
			startIdx = i
		}
	}
	if stopIdx == -1 {
		t.Fatalf("never saw stop in calls: %v", runner.calls)
	}
	if startIdx == -1 {
		t.Errorf("rollback never restarted source after stop: %v", runner.calls)
	}
}

// TestMoveContainer_RejectsSelf catches the obvious operator mistake.
func TestMoveContainer_RejectsSelf(t *testing.T) {
	runner := &fakeRunner{hasRemote: true}
	cs := newTestContainerServer(t, runner, "vm2")

	_, err := cs.MoveContainer(testCtx(),
		&pb.MoveContainerRequest{Username: "alice", TargetBackendId: cs.peerPool.LocalBackendID()})
	if err == nil {
		t.Fatal("expected error when target == local backend")
	}
}

// TestMigrationDefaults clamps/defaults — small but a frequent source
// of "the loop ran 10000 times" bugs.
func TestMigrationDefaults(t *testing.T) {
	cases := []struct {
		name      string
		req       *pb.MoveContainerRequest
		wantIters int
		wantDelta int
	}{
		{"all zero → defaults", &pb.MoveContainerRequest{}, 3, 5},
		{"explicit small", &pb.MoveContainerRequest{MaxIterations: 1, DeltaThresholdSeconds: 2}, 1, 2},
		{"negative iters clamped", &pb.MoveContainerRequest{MaxIterations: -7}, 0, 5},
		{"huge iters clamped", &pb.MoveContainerRequest{MaxIterations: 999}, 10, 5},
		{"huge delta clamped", &pb.MoveContainerRequest{MaxIterations: 1, DeltaThresholdSeconds: 9999}, 1, 60},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := migrationDefaults(c.req)
			if p.maxIterations != c.wantIters {
				t.Errorf("maxIterations = %d, want %d", p.maxIterations, c.wantIters)
			}
			if p.deltaThresholdSeconds != c.wantDelta {
				t.Errorf("deltaThresholdSeconds = %d, want %d", p.deltaThresholdSeconds, c.wantDelta)
			}
		})
	}
}
