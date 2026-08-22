package container

import (
	"errors"
	"testing"
	"time"
)

const testSSHKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMw0GUYQZVPWxSAC4T8RdKFGqzb8jxbFFM/SB6ILi1Ji test@host"

// stubJumpAccount replaces the host-side jump-account functions for the
// duration of the test. Not parallel-safe (package-level seam), so the
// tests that use it must not call t.Parallel.
func stubJumpAccount(t *testing.T, create func(username, key string, verbose bool) error) {
	t.Helper()
	prevCreate, prevAdd := createJumpServerAccountFn, addAuthorizedKeyFn
	createJumpServerAccountFn = create
	addAuthorizedKeyFn = func(string, string) error { return nil }
	t.Cleanup(func() {
		createJumpServerAccountFn, addAuthorizedKeyFn = prevCreate, prevAdd
	})
}

// TestCreate_JumpAccountRunsConcurrentlyWithGuestStages pins the overlap
// contract: the host-side jump account must NOT gate the guest stages.
// The stub refuses to finish until WaitForNetwork has been entered — under
// the old sequential order (jump account strictly before the network
// wait) that condition never becomes true, the stub times out, and the
// create fails, failing the test.
func TestCreate_JumpAccountRunsConcurrentlyWithGuestStages(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	networkWaited := make(chan struct{})
	backend := &stagesBackend{}
	var closeOnce bool
	backend.onWaitNetwork = func() {
		if !closeOnce {
			closeOnce = true
			close(networkWaited)
		}
	}

	stubJumpAccount(t, func(string, string, bool) error {
		select {
		case <-networkWaited:
			return nil
		case <-time.After(5 * time.Second):
			return errors.New("jump account still blocked when the network wait should already have run — create is sequential again")
		}
	})

	m := NewWithBackend(backend)
	opts := stagesOpts()
	opts.SSHKeys = []string{testSSHKey}

	if _, err := m.Create(opts); err != nil {
		t.Fatalf("Create: %v", err)
	}
}

// TestCreate_JumpAccountFailureStillFailsCreate pins the join: moving the
// account work off the critical path must not soften its error contract —
// a failed jump account fails the create and cleans up the container.
func TestCreate_JumpAccountFailureStillFailsCreate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	stubJumpAccount(t, func(string, string, bool) error {
		return errors.New("useradd exploded")
	})

	backend := &stagesBackend{}
	m := NewWithBackend(backend)
	log := newStageLog()
	m.SetStageObserver(log.observer())
	opts := stagesOpts()
	opts.SSHKeys = []string{testSSHKey}

	if _, err := m.Create(opts); err == nil {
		t.Fatal("Create succeeded despite a failed jump account")
	}
	if backend.deleteCalls == 0 {
		t.Error("failed jump account did not clean up the container")
	}
	if _, ok := log.durations[StageJumpAccount]; !ok {
		t.Errorf("jump_account stage not observed (observed: %v)", log.stages)
	}
	if _, ok := log.durations[StageTotal]; ok {
		t.Error("total observed on a failed create")
	}
}
