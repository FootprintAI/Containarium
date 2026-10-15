//go:build !windows

package agentbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The failure message must tell "the run never started" apart from "it
// started but the sidecar did not appear in time" (#2479).
func TestWaitForExitSidecar_FailureModesAreDistinct(t *testing.T) {
	t.Run("no record is reported as never started", func(t *testing.T) {
		_, err := waitForExitSidecar(t.TempDir(), "r", 100*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "never started") || strings.Contains(err.Error(), "timed out") {
			t.Fatalf("err = %v, want a never-started error", err)
		}
	})
	t.Run("record without sidecar is reported as timeout", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "r.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := waitForExitSidecar(dir, "r", 100*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "timed out") || strings.Contains(err.Error(), "never started") {
			t.Fatalf("err = %v, want a timeout error", err)
		}
	})
	t.Run("sidecar appearing mid-wait is returned", func(t *testing.T) {
		dir := t.TempDir()
		go func() {
			time.Sleep(150 * time.Millisecond)
			_ = os.WriteFile(filepath.Join(dir, "r.exit"), []byte("5 1"), 0o600)
		}()
		raw, err := waitForExitSidecar(dir, "r", 5*time.Second)
		if err != nil || string(raw) != "5 1" {
			t.Fatalf("raw=%q err=%v", raw, err)
		}
	})
}
