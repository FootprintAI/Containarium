//go:build !windows

package incus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeIncus writes an `incus` stand-in that records its arguments and applies
// the rules these tests pin. When nicACLs are given, the instance's NIC names
// them and a copy fails unless each was first created on the destination with
// `network acl create`, which is how Incus validates a copied tenant NIC. Incus refuses --instance-only when the copy
// source is a snapshot (a <container>/<snapshot> argument), failing with
// "--instance-only can't be passed when the source is a snapshot". It also
// refuses --refresh for a snapshot source, failing with
// "--refresh can only be used with instances".
//
// Every move test elsewhere substitutes a fake MigrationRunner, so the real
// command line ExecRunner builds was never run. That is how a flag Incus
// later started rejecting shipped.
func fakeIncus(t *testing.T, nicACLs ...string) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	bin = filepath.Join(dir, "incus")
	need := filepath.Join(dir, "need")
	created := filepath.Join(dir, "acls")
	query := filepath.Join(dir, "query.json")

	// The instance's NIC names these ACLs, as a tenant's container does.
	devices := `{"expanded_devices":{}}`
	if len(nicACLs) > 0 {
		devices = `{"expanded_devices":{"root":{"type":"disk","pool":"p","path":"/"},"eth0":{"type":"nic","network":"br","security.acls":"` + strings.Join(nicACLs, ",") + `"}}}`
		if err := os.WriteFile(need, []byte(strings.Join(nicACLs, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(query, []byte(devices), 0o644); err != nil {
		t.Fatal(err)
	}

	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + argsFile + `"
if [ "$1" = query ]; then cat "` + query + `"; exit 0; fi
if [ "$1" = network ] && [ "$2" = acl ] && [ "$3" = create ]; then
  name="${4#*:}"
  if grep -qx "$name" "` + created + `" 2>/dev/null; then
    echo "Error: Network ACL \"$name\" already exists" >&2
    exit 1
  fi
  echo "$name" >> "` + created + `"
  exit 0
fi
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
if [ "$1" = copy ] && [ -f "` + need + `" ]; then
  while read -r n; do
    if ! grep -qx "$n" "` + created + `" 2>/dev/null; then
      echo "Error: Failed instance creation: Invalid devices: Device validation failed for \"eth0\": Network ACL \"$n\" does not exist" >&2
      exit 1
    fi
  done < "` + need + `"
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

// A tenant's NIC names a guard ACL, and Incus requires it to exist on the
// destination when the copy creates the instance.
func TestExecRunner_CopyInitial_FailsWithoutTheTargetACL(t *testing.T) {
	bin, _ := fakeIncus(t, "tenant-guard")
	r := &ExecRunner{IncusPath: bin}

	err := r.CopyInitial("box", "sync0", "target-1", "")
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("want a missing-ACL error from the copy, got %v", err)
	}
}

func TestExecRunner_EnsureTargetACLs_CreatesEachReferencedACL(t *testing.T) {
	bin, argsFile := fakeIncus(t, "tenant-guard", "core-guard")
	r := &ExecRunner{IncusPath: bin}

	if err := r.EnsureTargetACLs("box", "target-1"); err != nil {
		t.Fatalf("EnsureTargetACLs: %v", err)
	}
	if err := r.CopyInitial("box", "sync0", "target-1", ""); err != nil {
		t.Fatalf("the copy must succeed once the ACLs exist on the target: %v", err)
	}

	joined := strings.Join(recordedArgs(t, argsFile), "\n")
	for _, name := range []string{"tenant-guard", "core-guard"} {
		if !strings.Contains(joined, "network acl create target-1:"+name) {
			t.Errorf("expected an ACL create for %q on the target; incus ran:\n%s", name, joined)
		}
	}
}

// The move can be retried, and the target's guard reconciler may already have
// created the ACL; an existing one is not an error.
func TestExecRunner_EnsureTargetACLs_ToleratesAnExistingACL(t *testing.T) {
	bin, _ := fakeIncus(t, "tenant-guard")
	r := &ExecRunner{IncusPath: bin}

	if err := r.EnsureTargetACLs("box", "target-1"); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := r.EnsureTargetACLs("box", "target-1"); err != nil {
		t.Fatalf("an ACL that already exists must not fail the move: %v", err)
	}
}

func TestExecRunner_EnsureTargetACLs_NothingToDoWithoutACLs(t *testing.T) {
	bin, argsFile := fakeIncus(t)
	r := &ExecRunner{IncusPath: bin}

	if err := r.EnsureTargetACLs("box", "target-1"); err != nil {
		t.Fatalf("EnsureTargetACLs: %v", err)
	}
	for _, line := range recordedArgs(t, argsFile) {
		if strings.Contains(line, "acl create") {
			t.Errorf("no ACL create expected for an instance with no ACLs, got %q", line)
		}
	}
}

// A pre-copy refresh runs while the container is serving traffic. Without
// --allow-inconsistent, Incus freezes a running source for the transfer on
// storage that cannot send a snapshot, which is an outage before the cutover
// that the reported downtime would not count. The final refresh runs after the
// source stops, so it stays consistent and does not carry the flag.
func TestExecRunner_CopyRefreshLive_DoesNotFreezeTheSource(t *testing.T) {
	bin, argsFile := fakeIncus(t)
	r := &ExecRunner{IncusPath: bin}

	if err := r.CopyRefreshLive("box", "sync1", "target-1", ""); err != nil {
		t.Fatalf("CopyRefreshLive: %v", err)
	}
	if err := r.CopyRefreshLive("box", "sync2", "target-1", "tenants"); err != nil {
		t.Fatalf("CopyRefreshLive with a pool: %v", err)
	}

	got := recordedArgs(t, argsFile)
	want := []string{
		"copy box target-1:box --refresh --allow-inconsistent",
		"copy box target-1:box --refresh --allow-inconsistent --storage tenants",
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("incus args = %q, want %q", got, want)
	}
}

func TestExecRunner_CopyRefresh_FinalStaysConsistent(t *testing.T) {
	bin, argsFile := fakeIncus(t)
	r := &ExecRunner{IncusPath: bin}

	if err := r.CopyRefresh("box", "final", "target-1", ""); err != nil {
		t.Fatalf("CopyRefresh: %v", err)
	}
	for _, line := range recordedArgs(t, argsFile) {
		if strings.Contains(line, "--allow-inconsistent") {
			t.Errorf("the final refresh must be consistent, got %q", line)
		}
	}
}

// A snapshot delete that never returns must not hold up the move's success
// response: the cleanup is best effort and gives up after a deadline.
func TestExecRunner_DeleteSnapshot_IsBounded(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "incus")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec sleep 20\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &ExecRunner{IncusPath: bin, SnapshotDeleteTimeout: 300 * time.Millisecond}

	start := time.Now()
	err := r.DeleteSnapshot("box", "sync0")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a delete that exceeded its deadline must report an error")
	}
	if elapsed > 5*time.Second {
		t.Errorf("DeleteSnapshot took %v; it must give up near the 300ms deadline", elapsed)
	}
}

// DeleteTarget removes the copy a failed move left on the target. -f stops it
// first if it is running, so the tenant is not left running on two backends.
func TestExecRunner_DeleteTarget_ForceDeletesOnTheRemote(t *testing.T) {
	bin, argsFile := fakeIncus(t)
	r := &ExecRunner{IncusPath: bin}

	if err := r.DeleteTarget("box", "target-1"); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}
	got := recordedArgs(t, argsFile)
	if len(got) != 1 || got[0] != "delete --force target-1:box" {
		t.Errorf("incus args = %q, want [delete --force target-1:box]", got)
	}
}

func TestExecRunner_DeleteTarget_IsBounded(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "incus")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec sleep 20\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &ExecRunner{IncusPath: bin, SnapshotDeleteTimeout: 300 * time.Millisecond}

	start := time.Now()
	if err := r.DeleteTarget("box", "target-1"); err == nil {
		t.Fatal("a delete that exceeded its deadline must report an error")
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("DeleteTarget took %v; it must give up near the deadline", time.Since(start))
	}
}
