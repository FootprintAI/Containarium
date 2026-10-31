package incus

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
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

	// EnsureTargetACLs makes sure every network ACL that `container`'s NICs
	// name exists on `targetRemote`. A copied instance keeps its NIC's
	// `security.acls`, and Incus refuses to create the instance on the
	// destination when a named ACL is missing ("Network ACL ... does not
	// exist"). A tenant's NIC names its guard ACL, so without this the first
	// copy of any tenant container fails.
	//
	// The ACL is created empty, so ingress is denied until the target daemon's
	// own guard reconciler replaces it with the rules for the tenant's members
	// on that host; the source's rules name addresses that are meaningless
	// there. An ACL that already exists is left alone. Equivalent to
	// `incus network acl create <remote>:<name>` for each ACL named.
	EnsureTargetACLs(container, targetRemote string) error

	// CopyInitial does the first full transfer of `container` with
	// snapshot `fromSnap` to `targetRemote`. `targetRemote` is the
	// name the source daemon's incusd uses for the destination — set
	// up once via `incus remote add` on the source. The destination
	// container takes the same name.
	//
	// storagePool, when non-empty, pins the destination pool the copy
	// lands in (`--storage`). Empty keeps Incus's own choice, which is the
	// destination's default pool — correct for an unencrypted container and
	// wrong for an encrypted one, whose data must land inside its tenant's
	// encryptionroot (#1203).
	//
	// Equivalent to: `incus copy <container>/<fromSnap> <remote>:<container> [--storage <pool>]`
	//
	// The source is a snapshot, which Incus copies as a standalone
	// instance without the container's other snapshots, so no
	// --instance-only is passed: Incus rejects that flag when the source
	// is a snapshot ("--instance-only can't be passed when the source is a
	// snapshot").
	CopyInitial(container, fromSnap, targetRemote, storagePool string) error

	// CopyRefreshLive is a CopyRefresh for the pre-copy iterations, which run
	// while the container is still serving traffic. It adds
	// --allow-inconsistent so Incus does not freeze a running source for the
	// transfer (it does on storage that cannot send a snapshot, which is an
	// outage before the cutover that the reported downtime would not count).
	// The copy may therefore be slightly inconsistent; that is fine because
	// the final CopyRefresh runs after the source stops and corrects it.
	CopyRefreshLive(container, fromSnap, targetRemote, storagePool string) error

	// CopyRefresh syncs the delta from the source to `targetRemote`.
	// Equivalent to:
	//   `incus copy <container> <remote>:<container> --refresh [--storage <pool>]`
	//
	// The source is the instance, not `fromSnap`: Incus accepts --refresh only
	// for an instance ("--refresh can only be used with instances"). The
	// snapshot taken just before each refresh is part of the instance, so it
	// travels with the copy, and a btrfs/zfs source can send the increment
	// between snapshots. `fromSnap` is kept in the signature to name that
	// snapshot for callers and logs.
	// With ZFS/btrfs storage on both ends, this is a fast incremental
	// (zfs-send-style); with dir-pool storage it falls back to file
	// rsync, which works but isn't sub-second.
	CopyRefresh(container, fromSnap, targetRemote, storagePool string) error

	// DeleteTarget force-deletes `container` on `targetRemote` (stopping it
	// first if it is running). The move uses it to remove the copy it made
	// there when the move fails, so the tenant is never left running on two
	// backends. The move calls it only after its own first copy succeeded,
	// when that instance is known to be its own. A container that is already
	// gone is not an error. Equivalent to
	// `incus delete --force <remote>:<container>`.
	DeleteTarget(container, targetRemote string) error

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

	// SnapshotDeleteTimeout bounds one cleanup delete: `incus snapshot delete`
	// and the target delete after a failed move. The cleanup is best effort, so
	// a delete that never returns must not hold up the response. Zero means
	// defaultSnapshotDeleteTimeout.
	SnapshotDeleteTimeout time.Duration
}

// defaultSnapshotDeleteTimeout is generous for deleting a snapshot, which
// takes seconds even on a large btrfs or zfs volume.
const defaultSnapshotDeleteTimeout = 2 * time.Minute

func (e *ExecRunner) incus(args ...string) error {
	return e.incusCtx(context.Background(), args...)
}

// incusCtx runs incus and kills it when ctx ends.
func (e *ExecRunner) incusCtx(ctx context.Context, args ...string) error {
	bin := e.IncusPath
	if bin == "" {
		bin = "incus"
	}
	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- args are validated by callers
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("incus %s: timed out: %w\nOutput: %s", strings.Join(args, " "), ctx.Err(), string(out))
		}
		return fmt.Errorf("incus %s: %w\nOutput: %s", strings.Join(args, " "), err, string(out))
	}
	return nil
}

// Snapshot — `incus snapshot create <container> <snapshot>` (#1392).
//
// `incus snapshot` is a command GROUP in Incus 6.x, not a verb. This used to
// call `incus snapshot <container> <snapshot>`, which that version rejects
// with `unknown command "<container>" for "incus snapshot"` — so MoveContainer
// failed on its very first call, before any copy. No test caught it because
// every move test substitutes a fake MigrationRunner and the real ExecRunner
// is wired only in production; the migration logic was covered, the CLI
// surface under it was not covered at all.
//
// If the snapshot already exists (rerun after a partial failure) the CLI errors
// with "already exists" — swallowed to keep retry idempotent.
func (e *ExecRunner) Snapshot(container, snapshot string) error {
	err := e.incus("snapshot", "create", container, snapshot)
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "already exists") {
		return nil
	}
	return err
}

// DeleteSnapshot — `incus snapshot delete <container> <snapshot>` (#1392).
//
// This used to call `incus delete <container>/<snapshot>`, which Incus 6.x
// rejects with `Invalid instance name`. That message matches neither of the
// absent-snapshot strings below, so a failed cleanup surfaced as a hard error
// rather than being swallowed — and every migration left its sync snapshots
// behind, pinning disk on both hosts.
func (e *ExecRunner) DeleteSnapshot(container, snapshot string) error {
	timeout := e.SnapshotDeleteTimeout
	if timeout <= 0 {
		timeout = defaultSnapshotDeleteTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := e.incusCtx(ctx, "snapshot", "delete", container, snapshot)
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "doesn't exist") {
		return nil
	}
	return err
}

// incusOutput runs incus and returns its standard output.
func (e *ExecRunner) incusOutput(args ...string) ([]byte, error) {
	bin := e.IncusPath
	if bin == "" {
		bin = "incus"
	}
	cmd := exec.Command(bin, args...) // #nosec G204 -- args are validated by callers
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		return nil, fmt.Errorf("incus %s: %w\nOutput: %s", strings.Join(args, " "), err, stderr)
	}
	return out, nil
}

func (e *ExecRunner) EnsureTargetACLs(container, targetRemote string) error {
	out, err := e.incusOutput("query", "/1.0/instances/"+container)
	if err != nil {
		return fmt.Errorf("read %s's devices: %w", container, err)
	}
	var inst struct {
		ExpandedDevices map[string]map[string]string `json:"expanded_devices"`
	}
	if err := json.Unmarshal(out, &inst); err != nil {
		return fmt.Errorf("parse %s's devices: %w", container, err)
	}

	seen := map[string]bool{}
	for _, dev := range inst.ExpandedDevices {
		for _, name := range strings.Split(dev["security.acls"], ",") {
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			err := e.incus("network", "acl", "create", targetRemote+":"+name,
				"--description", "created for an incoming migration; the target daemon replaces its rules")
			if err != nil && !strings.Contains(err.Error(), "already exists") {
				return fmt.Errorf("create network ACL %q on %s: %w", name, targetRemote, err)
			}
		}
	}
	return nil
}

func (e *ExecRunner) DeleteTarget(container, targetRemote string) error {
	timeout := e.SnapshotDeleteTimeout
	if timeout <= 0 {
		timeout = defaultSnapshotDeleteTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := e.incusCtx(ctx, "delete", "--force", targetRemote+":"+container)
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "doesn't exist") {
		return nil
	}
	return err
}

func (e *ExecRunner) CopyInitial(container, fromSnap, targetRemote, storagePool string) error {
	src := fmt.Sprintf("%s/%s", container, fromSnap)
	dst := fmt.Sprintf("%s:%s", targetRemote, container)
	args := []string{"copy", src, dst}
	if storagePool != "" {
		args = append(args, "--storage", storagePool)
	}
	return e.incus(args...)
}

func (e *ExecRunner) CopyRefresh(container, fromSnap, targetRemote, storagePool string) error {
	_ = fromSnap // the refresh copies the instance; see MigrationRunner.CopyRefresh
	dst := fmt.Sprintf("%s:%s", targetRemote, container)
	args := []string{"copy", container, dst, "--refresh"}
	if storagePool != "" {
		args = append(args, "--storage", storagePool)
	}
	return e.incus(args...)
}

func (e *ExecRunner) CopyRefreshLive(container, fromSnap, targetRemote, storagePool string) error {
	_ = fromSnap // the refresh copies the instance; see MigrationRunner.CopyRefresh
	dst := fmt.Sprintf("%s:%s", targetRemote, container)
	args := []string{"copy", container, dst, "--refresh", "--allow-inconsistent"}
	if storagePool != "" {
		args = append(args, "--storage", storagePool)
	}
	return e.incus(args...)
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
