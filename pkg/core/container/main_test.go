package container

import (
	"os"
	"testing"
)

// TestMain keeps the keyless create path (#2489) from running host useradd in
// unit tests: every test that creates a box without SSH keys would otherwise
// hit the real EnsureJumpServerAccount. Tests that care stub it themselves.
func TestMain(m *testing.M) {
	ensureJumpServerAccountFn = func(string) error { return nil }
	// A failed create now removes the host account it made (#2850). No test may
	// reach the real id/userdel: report every account as pre-existing (so none
	// is removed) unless a test stubs the lifecycle itself.
	userExistsFn = func(string) bool { return true }
	deleteJumpServerAccountFn = func(string, bool) error { return nil }
	os.Exit(m.Run())
}
