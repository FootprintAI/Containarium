package container

import (
	"errors"
	"testing"
)

// stubEnsureJumpAccount replaces the host-side ensure seam for one test.
// Not parallel-safe (package-level seam), same as stubJumpAccount.
func stubEnsureJumpAccount(t *testing.T, ensure func(username string) error) {
	t.Helper()
	prev := ensureJumpServerAccountFn
	ensureJumpServerAccountFn = ensure
	t.Cleanup(func() { ensureJumpServerAccountFn = prev })
}

// TestCreate_NoSSHKeysStillCreatesJumpAccount pins #2489: a box created with
// no SSH keys (e.g. by a hosted control plane for a user who registered none
// and connects with a certificate) must still get its host-side jump-server
// account. Without it the sentinel has nothing to route to and every later
// add-key fails with "host user does not exist".
func TestCreate_NoSSHKeysStillCreatesJumpAccount(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	var ensured []string
	stubEnsureJumpAccount(t, func(u string) error { ensured = append(ensured, u); return nil })
	stubJumpAccount(t, func(string, string, bool) error {
		t.Error("key-seeded CreateJumpServerAccount must not run when there are no keys")
		return nil
	})

	m := NewWithBackend(&stagesBackend{})
	opts := stagesOpts() // no SSHKeys
	if _, err := m.Create(opts); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(ensured) != 1 || ensured[0] != opts.Username {
		t.Fatalf("EnsureJumpServerAccount calls = %v, want exactly [%q]", ensured, opts.Username)
	}
}

// TestCreate_NoSSHKeysJumpAccountFailureFailsCreate: the keyless path keeps the
// same error contract as the keyed one — a failed account fails the create and
// cleans the container up, instead of reporting success on an unreachable box.
func TestCreate_NoSSHKeysJumpAccountFailureFailsCreate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	stubEnsureJumpAccount(t, func(string) error { return errors.New("useradd exploded") })

	backend := &stagesBackend{}
	m := NewWithBackend(backend)
	if _, err := m.Create(stagesOpts()); err == nil {
		t.Fatal("Create succeeded despite a failed jump account")
	}
	if backend.deleteCalls == 0 {
		t.Error("failed jump account did not clean up the container")
	}
}
