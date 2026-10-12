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
	os.Exit(m.Run())
}
