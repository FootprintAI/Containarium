package incus

import (
	"fmt"
	"os/exec"
	"strings"
)

// MigrationRunner is the small surface the migration orchestrator
// needs from incus. It exists as an interface so tests can swap in a
// fake that doesn't actually shell out — without it, every
// MoveContainer test would need a real Incus + a real remote daemon
// to copy to. The orchestration logic (snapshot ordering, delta
// iteration, cutover sequencing) is the interesting thing to test;
// the actual `incus copy` shell-out is well-trodden and not worth
// re-verifying in unit tests.
type MigrationRunner interface {
	// Snapshot creates a snapshot of the named container.
	// Idempotent on retry: if the snapshot exists, returns nil.
	Snapshot(container, snapshot string) error

	// DeleteSnapshot removes a previously-created snapshot. Used at
	// the end of a successful migration to clean up the sync<N> trail
	// of snapshots we left during pre-copy. No-op if the snapshot
	// doesn't exist.
	DeleteSnapshot(container, snapshot string) error

	// CopyInitial does the first full transfer of `container` with
	// snapshot `fromSnap` to `targetRemote`. `targetRemote` is the
	// name the source daemon's incusd uses for the destination — set
	// up once via `incus remote add` on the source. The destination
	// container takes the same name.
	//
	// Equivalent to: `incus copy <container>/<fromSnap> <remote>:<container> --instance-only`
	CopyInitial(container, fromSnap, targetRemote string) error

	// CopyRefresh syncs the delta from the source's previous-state
	// snapshot to `targetRemote`. Equivalent to:
	//   `incus copy <container>/<fromSnap> <remote>:<container> --refresh`
	// With ZFS/btrfs storage on both ends, this is a fast incremental
	// (zfs-send-style); with dir-pool storage it falls back to file
	// rsync, which works but isn't sub-second.
	CopyRefresh(container, fromSnap, targetRemote string) error

	// Stop stops a container. Used at the very start of cutover; any
	// final state changes after this point are caught by the post-stop
	// snapshot+refresh.
	Stop(container string) error

	// Start starts a (possibly migrated) container, returning when
	// it's running. The source-side orchestrator uses this to undo a
	// pre-cutover Stop on failure; the destination-side adopter uses
	// it after AdoptMigratedContainer ensures host-user state is set
	// up.
	Start(container string) error

	// HasRemote reports whether the source's incusd knows about
	// `remoteName` as a destination it can copy to. The migration
	// fails fast if not — the operator needs to `incus remote add`
	// first. Auto-bootstrap of remotes is a separate follow-up.
	HasRemote(remoteName string) (bool, error)
}

// ExecRunner is the production MigrationRunner. It shells out to the
// `incus` CLI on the host. Lightweight and matches how the rest of
// this package shells out to `zfs` / `incus` for storage and exec
// operations — keeps the operational mental model identical.
type ExecRunner struct {
	// Path to the incus binary. Empty means look on $PATH.
	IncusPath string
}

func (e *ExecRunner) incus(args ...string) error {
	bin := e.IncusPath
	if bin == "" {
		bin = "incus"
	}
	cmd := exec.Command(bin, args...) // #nosec G204 -- args are validated by callers
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("incus %s: %w\nOutput: %s", strings.Join(args, " "), err, string(out))
	}
	return nil
}

// Snapshot — `incus snapshot <container> <snapshot>`. If the snapshot
// already exists (rerun after partial failure), the underlying CLI
// errors with "snapshot already exists" — we swallow that to keep
// retry idempotent.
func (e *ExecRunner) Snapshot(container, snapshot string) error {
	err := e.incus("snapshot", container, snapshot)
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "already exists") {
		return nil
	}
	return err
}

func (e *ExecRunner) DeleteSnapshot(container, snapshot string) error {
	err := e.incus("delete", container+"/"+snapshot)
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "doesn't exist") {
		return nil
	}
	return err
}

func (e *ExecRunner) CopyInitial(container, fromSnap, targetRemote string) error {
	src := fmt.Sprintf("%s/%s", container, fromSnap)
	dst := fmt.Sprintf("%s:%s", targetRemote, container)
	return e.incus("copy", src, dst, "--instance-only")
}

func (e *ExecRunner) CopyRefresh(container, fromSnap, targetRemote string) error {
	src := fmt.Sprintf("%s/%s", container, fromSnap)
	dst := fmt.Sprintf("%s:%s", targetRemote, container)
	return e.incus("copy", src, dst, "--refresh")
}

func (e *ExecRunner) Stop(container string) error {
	err := e.incus("stop", container)
	if err == nil {
		return nil
	}
	// Already stopped → still success.
	if strings.Contains(err.Error(), "is not running") {
		return nil
	}
	return err
}

func (e *ExecRunner) Start(container string) error {
	err := e.incus("start", container)
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "is already running") {
		return nil
	}
	return err
}

// HasRemote — we just shell out to `incus remote list --format csv`
// and grep for the name. Cheap, no need for the upstream Go client.
func (e *ExecRunner) HasRemote(remoteName string) (bool, error) {
	bin := e.IncusPath
	if bin == "" {
		bin = "incus"
	}
	cmd := exec.Command(bin, "remote", "list", "--format", "csv") // #nosec G204 -- fixed args
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("incus remote list: %w\nOutput: %s", err, string(out))
	}
	for _, line := range strings.Split(string(out), "\n") {
		// CSV row: name,url,protocol,public,static,...
		if strings.HasPrefix(line, remoteName+",") {
			return true, nil
		}
	}
	return false, nil
}
