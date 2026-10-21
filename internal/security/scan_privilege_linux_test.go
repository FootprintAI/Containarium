//go:build linux

package security

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// #2888: clamscan pre-checks files with access(2), which ignores
// CAP_DAC_READ_SEARCH when the REAL uid is not 0. This runs the real privilege
// arguments against a real root-only file, with `test -r` standing in for
// clamscan (dash's `test -r` is access(2)). It needs root and setpriv, so it
// skips on an ordinary CI runner; the check has also been done by hand on a real
// box, see the PR.
func TestScanPrivilegeArgs_AccessCheckSeesARootOnlyFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to set up a root-only file and to run setpriv")
	}
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Skip("setpriv not installed")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("setpriv", append(scanPrivilegeArgs()[1:], "sh", "-c", `test -r "$F"`)...)
	cmd.Env = append(os.Environ(), "F="+secret)
	if err := cmd.Run(); err != nil {
		t.Fatalf("the scan user cannot pass an access(R_OK) check on a root-only file: %v", err)
	}
	// ...and it must still not be able to write there as itself.
	w := exec.Command("setpriv", append(scanPrivilegeArgs()[1:], "sh", "-c", `echo x > "$F.new"`)...)
	w.Env = append(os.Environ(), "F="+secret)
	if err := w.Run(); err == nil {
		t.Fatal("the scan user created a file in a root-only directory; it must not be able to write")
	}
}
