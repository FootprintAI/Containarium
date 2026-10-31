//go:build !windows

package incus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeIncus writes an `incus` stand-in that records its arguments and applies
// the two rules these tests pin. Incus refuses --instance-only when the copy
// source is a snapshot (a <container>/<snapshot> argument), failing with
// "--instance-only can't be passed when the source is a snapshot". It also
// refuses --refresh for a snapshot source, failing with
// "--refresh can only be used with instances".
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
refresh=0
snapshot_source=0
for a in "$@"; do
  case "$a" in
    --instance-only) instance_only=1 ;;
    --refresh) refresh=1 ;;
    -*) ;;
    */*) snapshot_source=1 ;;
  esac
done
if [ "$instance_only" = 1 ] && [ "$snapshot_source" = 1 ]; then
  echo "Error: --instance-only can't be passed when the source is a snapshot" >&2
  exit 1
fi
if [ "$refresh" = 1 ] && [ "$snapshot_source" = 1 ]; then
  echo "Error: --refresh can only be used with instances" >&2
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

// A refresh copies the instance itself: Incus accepts --refresh only for an
// instance source. The instance carries the sync snapshots, which is what
// lets btrfs/zfs send an increment.
func TestExecRunner_CopyRefresh_CopiesTheInstance(t *testing.T) {
	bin, argsFile := fakeIncus(t)
	r := &ExecRunner{IncusPath: bin}

	if err := r.CopyRefresh("box", "sync1", "target-1", ""); err != nil {
		t.Fatalf("CopyRefresh failed against an incus that rejects --refresh on a snapshot source: %v", err)
	}

	got := recordedArgs(t, argsFile)
	if len(got) != 1 || got[0] != "copy box target-1:box --refresh" {
		t.Errorf("incus args = %q, want [copy box target-1:box --refresh]", got)
	}
}

func TestExecRunner_CopyRefresh_PinsTheDestinationPool(t *testing.T) {
	bin, argsFile := fakeIncus(t)
	r := &ExecRunner{IncusPath: bin}

	if err := r.CopyRefresh("box", "final", "target-1", "tenants"); err != nil {
		t.Fatalf("CopyRefresh: %v", err)
	}

	got := recordedArgs(t, argsFile)
	if len(got) != 1 || got[0] != "copy box target-1:box --refresh --storage tenants" {
		t.Errorf("incus args = %q, want [copy box target-1:box --refresh --storage tenants]", got)
	}
}
