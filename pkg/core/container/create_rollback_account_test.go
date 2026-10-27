package container

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// accountLog records the host-account operations a Create makes, in order, so
// a test can assert not just that the account was removed but that the removal
// came after the (concurrent) creation finished.
type accountLog struct {
	mu     sync.Mutex
	events []string
}

func (l *accountLog) add(e string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *accountLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

func (l *accountLog) joined() string { return strings.Join(l.snapshot(), ",") }

// stubAccountLifecycle replaces every host-side account operation Create makes
// (create, ensure, exists, delete) for the test. existed is what `id <user>`
// reports BEFORE the create starts. Not parallel-safe (package-level seams).
func stubAccountLifecycle(t *testing.T, existed bool, createDelay time.Duration) *accountLog {
	t.Helper()
	log := &accountLog{}
	prevCreate, prevAdd, prevEnsure, prevExists, prevDelete :=
		createJumpServerAccountFn, addAuthorizedKeyFn, ensureJumpServerAccountFn, userExistsFn, deleteJumpServerAccountFn
	createJumpServerAccountFn = func(string, string, bool) error {
		log.add("create:start")
		time.Sleep(createDelay)
		log.add("create:end")
		return nil
	}
	ensureJumpServerAccountFn = func(string) error {
		log.add("ensure:start")
		time.Sleep(createDelay)
		log.add("ensure:end")
		return nil
	}
	addAuthorizedKeyFn = func(string, string) error { return nil }
	userExistsFn = func(string) bool { return existed }
	deleteJumpServerAccountFn = func(user string, _ bool) error {
		log.add("delete:" + user)
		return nil
	}
	t.Cleanup(func() {
		createJumpServerAccountFn, addAuthorizedKeyFn, ensureJumpServerAccountFn, userExistsFn, deleteJumpServerAccountFn =
			prevCreate, prevAdd, prevEnsure, prevExists, prevDelete
	})
	return log
}

// #2850: a create that fails after the host jump account was started must not
// leave that account behind, and must wait for the concurrent creation to
// finish first (otherwise the account is made after the removal).
func TestCreate_FailureAfterTheAccountStartedRemovesTheAccountItMade(t *testing.T) {
	for _, tc := range []struct {
		name string
		keys []string
		made string // the event that proves the creating call ran
	}{
		{"with ssh keys", []string{testSSHKey}, "create:end"},
		{"keyless", nil, "ensure:end"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			log := stubAccountLifecycle(t, false, 60*time.Millisecond)
			backend := &stagesBackend{waitNetworkErr: errors.New("timeout waiting for container network")}
			opts := stagesOpts()
			opts.SSHKeys = tc.keys

			_, err := NewWithBackend(backend).Create(opts)
			if err == nil || !strings.Contains(err.Error(), "timeout waiting for container network") {
				t.Fatalf("Create = %v, want the network failure", err)
			}
			if backend.deleteCalls == 0 {
				t.Error("the container was not rolled back")
			}
			// Create has returned, so the removal must already have happened,
			// and strictly after the account creation completed.
			ev := log.snapshot()
			if len(ev) == 0 || ev[len(ev)-1] != "delete:alice" {
				t.Fatalf("events = %v, want the account removed last", ev)
			}
			madeAt, deletedAt := -1, -1
			for i, e := range ev {
				if e == tc.made {
					madeAt = i
				}
				if e == "delete:alice" {
					deletedAt = i
				}
			}
			if madeAt < 0 || deletedAt < madeAt {
				t.Fatalf("events = %v: the account was removed before its creation finished", ev)
			}
		})
	}
}

// An account that was there before this create started belongs to someone
// else (a prior box, a CLI that made it first): a failed create must not
// delete it.
func TestCreate_FailureNeverRemovesAnAccountThatExistedBeforehand(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	log := stubAccountLifecycle(t, true, 0)
	backend := &stagesBackend{waitNetworkErr: errors.New("timeout waiting for container network")}
	opts := stagesOpts()
	opts.SSHKeys = []string{testSSHKey}

	if _, err := NewWithBackend(backend).Create(opts); err == nil {
		t.Fatal("Create succeeded")
	}
	if strings.Contains(log.joined(), "delete:") {
		t.Fatalf("events = %v: removed an account this create did not make", log.snapshot())
	}
}

func TestCreate_SuccessKeepsTheAccount(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	log := stubAccountLifecycle(t, false, 0)
	opts := stagesOpts()
	opts.SSHKeys = []string{testSSHKey}

	if _, err := NewWithBackend(&stagesBackend{}).Create(opts); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if strings.Contains(log.joined(), "delete:") {
		t.Fatalf("events = %v: a successful create removed its account", log.snapshot())
	}
}

// A failed account creation can leave a partial account; the existing contract
// (the create fails and the container is cleaned up) now also removes it.
func TestCreate_FailedAccountCreationAlsoRemovesAnyPartialAccount(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	log := stubAccountLifecycle(t, false, 0)
	createJumpServerAccountFn = func(string, string, bool) error {
		log.add("create:partial")
		return errors.New("useradd exploded")
	}
	opts := stagesOpts()
	opts.SSHKeys = []string{testSSHKey}

	_, err := NewWithBackend(&stagesBackend{}).Create(opts)
	if err == nil || !strings.Contains(err.Error(), "useradd exploded") {
		t.Fatalf("Create = %v, want the account failure", err)
	}
	if got := log.joined(); got != "create:partial,delete:alice" {
		t.Fatalf("events = %q, want the partial account removed", got)
	}
}

// The removal is best-effort: if it fails, the caller still sees the real
// cause of the failed create, not the cleanup's error.
func TestCreate_AccountRemovalFailureDoesNotMaskTheCause(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	stubAccountLifecycle(t, false, 0)
	deleteJumpServerAccountFn = func(string, bool) error { return errors.New("userdel: user alice is currently used") }
	backend := &stagesBackend{waitNetworkErr: errors.New("timeout waiting for container network")}
	opts := stagesOpts()
	opts.SSHKeys = []string{testSSHKey}

	_, err := NewWithBackend(backend).Create(opts)
	if err == nil || !strings.Contains(err.Error(), "timeout waiting for container network") || strings.Contains(err.Error(), "userdel") {
		t.Fatalf("Create = %v, want only the network failure", err)
	}
}

// A hung account step must not hang a failing create: past the backstop the
// create reports its real cause, and the account (which may still be being
// made) is left alone rather than removed under the goroutine.
func TestCreate_FailureDoesNotWaitForeverOnAHungAccountStep(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	log := stubAccountLifecycle(t, false, 0)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	createJumpServerAccountFn = func(string, string, bool) error {
		log.add("create:start")
		<-release
		return nil
	}
	prev := jumpAccountJoinTimeout
	jumpAccountJoinTimeout = 50 * time.Millisecond
	t.Cleanup(func() { jumpAccountJoinTimeout = prev })

	backend := &stagesBackend{waitNetworkErr: errors.New("timeout waiting for container network")}
	opts := stagesOpts()
	opts.SSHKeys = []string{testSSHKey}

	start := time.Now()
	_, err := NewWithBackend(backend).Create(opts)
	if err == nil || !strings.Contains(err.Error(), "timeout waiting for container network") {
		t.Fatalf("Create = %v, want the network failure", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("took %s: the failing create waited for the hung account step", time.Since(start))
	}
	if strings.Contains(log.joined(), "delete:") {
		t.Fatalf("events = %v: removed an account that was still being created", log.snapshot())
	}
}
