//go:build !windows

package incus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeIncus writes an `incus` stand-in that records its arguments and applies
// the one rule these tests pin: Incus refuses --instance-only when the copy
// source is a snapshot (a <container>/<snapshot> argument), failing with
// "--instance-only can't be passed when the source is a snapshot".
//
// Every move test elsewhere substitutes a fake MigrationRunner, so the real
// command line ExecRunner builds was never run. That is how a flag Incus
// later started rejecting shipped.
func fakeIncus(t *testing.T) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	bin = filepath.Join(dir, "incus")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + argsFile + `"
instance_only=0
snapshot_source=0
for a in "$@"; do
  case "$a" in
    --instance-only) instance_only=1 ;;
    -*) ;;
    */*) snapshot_source=1 ;;
  esac
done
if [ "$instance_only" = 1 ] && [ "$snapshot_source" = 1 ]; then
  echo "Error: --instance-only can't be passed when the source is a snapshot" >&2
  exit 1
fi
exit 0
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

func recordedArgs(t *testing.T, argsFile string) []string {
	t.Helper()
	b, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("incus was never run: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func TestExecRunner_CopyInitial_FromASnapshotIsAccepted(t *testing.T) {
	bin, argsFile := fakeIncus(t)
	r := &ExecRunner{IncusPath: bin}

	if err := r.CopyInitial("box", "sync0", "target-1", ""); err != nil {
		t.Fatalf("CopyInitial failed against an incus that rejects --instance-only on a snapshot source: %v", err)
	}

	got := recordedArgs(t, argsFile)
	if len(got) != 1 || got[0] != "copy box/sync0 target-1:box" {
		t.Errorf("incus args = %q, want exactly [copy box/sync0 target-1:box]", got)
	}
}

func TestExecRunner_CopyInitial_PinsTheDestinationPool(t *testing.T) {
	bin, argsFile := fakeIncus(t)
	r := &ExecRunner{IncusPath: bin}

	if err := r.CopyInitial("box", "sync0", "target-1", "tenants"); err != nil {
		t.Fatalf("CopyInitial: %v", err)
	}

	got := recordedArgs(t, argsFile)
	if len(got) != 1 || got[0] != "copy box/sync0 target-1:box --storage tenants" {
		t.Errorf("incus args = %q, want [copy box/sync0 target-1:box --storage tenants]", got)
	}
}

func TestExecRunner_CopyRefresh_StillRefreshes(t *testing.T) {
	bin, argsFile := fakeIncus(t)
	r := &ExecRunner{IncusPath: bin}

	if err := r.CopyRefresh("box", "sync1", "target-1", ""); err != nil {
		t.Fatalf("CopyRefresh: %v", err)
	}

	got := recordedArgs(t, argsFile)
	if len(got) != 1 || got[0] != "copy box/sync1 target-1:box --refresh" {
		t.Errorf("incus args = %q, want [copy box/sync1 target-1:box --refresh]", got)
	}
}
