// Package zfscrypt drives the `zfs` CLI for per-tenant native encryption.
//
// Phase 3/4 of docs/ZFS-PER-CONTAINER-ENCRYPTION-DESIGN.md: the dataset
// operations the container lifecycle hooks call. Key custody lives in
// pkg/core/zfskey; this package only knows how to hand a key to ZFS and
// how to ask what ZFS did with it.
//
// # Verification status
//
// The command forms below are derived from the design doc and the ZFS
// documentation, and are exercised in tests against a fake runner. They
// have NOT been executed against a real pool — see #1200: no reachable
// environment can host one (the dev box is an LXC container with no zfs
// device registered and no /dev/kvm). A fake agreeing with itself proves
// the orchestration, not the ZFS semantics.
//
// Every assumption about what `zfs` does is therefore called out at the
// call site, so a reviewer with a real pool can check them one by one
// rather than re-deriving them. The unverified assumptions are:
//
//   - `-o keylocation=file:///dev/stdin` with the raw key on stdin loads
//     a key without it ever touching argv or a temp file.
//   - `zfs unload-key` fails, rather than succeeding silently, while a
//     dataset under the encryptionroot is still mounted.
//   - `keystatus` reports exactly "available" or "unavailable".
package zfscrypt

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/footprintai/containarium/pkg/core/zfskey"
)

// Runner executes a zfs command. Declared as an interface so the hook
// logic is testable without a pool, and so the daemon can inject a
// runner that logs or that targets a remote host.
type Runner interface {
	// Run executes `zfs <args...>`, writing stdin to the child's stdin
	// when non-nil, and returns stdout and stderr.
	Run(ctx context.Context, stdin []byte, args ...string) (stdout, stderr string, err error)
}

// ExecRunner runs the host's zfs binary.
type ExecRunner struct{}

// Run implements Runner against the real `zfs` command.
func (ExecRunner) Run(ctx context.Context, stdin []byte, args ...string) (string, string, error) {
	// #nosec G204 -- the binary is the literal "zfs"; args are built by
	// this package from validated dataset names, never from raw caller
	// input (see validateDataset).
	cmd := exec.CommandContext(ctx, "zfs", args...)
	if stdin != nil {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

// Manager performs the encryption-related dataset operations.
type Manager struct {
	run Runner
}

// NewManager constructs a Manager over a Runner. Passing nil uses the
// real zfs binary.
func NewManager(r Runner) *Manager {
	if r == nil {
		r = ExecRunner{}
	}
	return &Manager{run: r}
}

// KeyStatus mirrors ZFS's `keystatus` property.
type KeyStatus string

const (
	// KeyAvailable means the key is loaded: the dataset can be mounted
	// and its contents read.
	KeyAvailable KeyStatus = "available"
	// KeyUnavailable means the key is not loaded: the dataset is
	// ciphertext, including to host root. This is the state a stopped
	// container's dataset must be in (#1201).
	KeyUnavailable KeyStatus = "unavailable"
)

// validateDataset rejects names that could turn a dataset argument into
// something else — a flag, a second argument, or a shell-ish string.
//
// The name is built by the daemon from a pool and a container name, so
// this is defence in depth rather than the primary control; it is cheap
// and the failure mode (operating on the wrong dataset) is destructive.
func validateDataset(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("dataset name is required")
	case strings.HasPrefix(name, "-"):
		return fmt.Errorf("invalid dataset name %q: leading dash would be read as a flag", name)
	case strings.ContainsAny(name, " \t\n\r"):
		return fmt.Errorf("invalid dataset name %q: contains whitespace", name)
	case !strings.Contains(name, "/"):
		// Every container dataset lives under a pool. A bare name is
		// the pool root itself, and encrypting or destroying that is
		// never what the caller meant.
		return fmt.Errorf("invalid dataset name %q: expected <pool>/<path>", name)
	}
	return nil
}

// CreateEncrypted creates a dataset with ZFS native encryption enabled,
// keyed by the supplied key.
//
// The key travels on **stdin**, never on argv and never through a temp
// file: argv is world-readable through /proc/<pid>/cmdline for the life
// of the process, and a temp file leaves key material on disk, which is
// the one thing the whole design forbids.
func (m *Manager) CreateEncrypted(ctx context.Context, dataset string, key zfskey.Key) error {
	if err := validateDataset(dataset); err != nil {
		return err
	}
	if key.IsZero() {
		return fmt.Errorf("refusing to create %s with an empty key", dataset)
	}

	// ASSUMPTION (unverified against a real pool, #1200): passing the
	// raw key on stdin with keylocation=file:///dev/stdin is accepted by
	// `zfs create`, and keyformat=raw expects exactly 32 bytes — which
	// zfskey.Key already guarantees.
	_, stderr, err := m.run.Run(ctx, key.Bytes(),
		"create",
		"-o", "encryption=on",
		"-o", "keyformat=raw",
		"-o", "keylocation=file:///dev/stdin",
		dataset,
	)
	if err != nil {
		return fmt.Errorf("create encrypted dataset %s: %w: %s", dataset, err, strings.TrimSpace(stderr))
	}
	return nil
}

// LoadKey makes an encrypted dataset readable. It is a no-op when the
// key is already loaded, so a restarted daemon re-running the pre-start
// hook does not fail.
func (m *Manager) LoadKey(ctx context.Context, dataset string, key zfskey.Key) error {
	if err := validateDataset(dataset); err != nil {
		return err
	}
	if key.IsZero() {
		return fmt.Errorf("refusing to load an empty key for %s", dataset)
	}

	status, err := m.KeyStatus(ctx, dataset)
	if err != nil {
		return err
	}
	if status == KeyAvailable {
		return nil
	}

	_, stderr, err := m.run.Run(ctx, key.Bytes(),
		"load-key", "-L", "file:///dev/stdin", dataset)
	if err != nil {
		return fmt.Errorf("load key for %s: %w: %s", dataset, err, strings.TrimSpace(stderr))
	}
	return nil
}

// UnloadKey drops the key from the kernel, returning the dataset to
// ciphertext (#1201).
//
// Returns ErrKeyInUse when ZFS refuses because something under the
// encryptionroot is still mounted — the expected case when a tenant has
// another container running, and not an error the caller should treat as
// a failure.
func (m *Manager) UnloadKey(ctx context.Context, dataset string) error {
	if err := validateDataset(dataset); err != nil {
		return err
	}

	status, err := m.KeyStatus(ctx, dataset)
	if err != nil {
		return err
	}
	if status == KeyUnavailable {
		// Already ciphertext; nothing to do.
		return nil
	}

	_, stderr, err := m.run.Run(ctx, nil, "unload-key", dataset)
	if err != nil {
		// ASSUMPTION (unverified, #1200): ZFS refuses with a
		// "busy"/"in use" message rather than silently succeeding while
		// a dataset under the encryptionroot is mounted. If it instead
		// succeeded, a co-tenant's running container would lose its key
		// — which is why this is called out for a reviewer with a pool.
		if isKeyInUse(stderr) {
			return ErrKeyInUse
		}
		return fmt.Errorf("unload key for %s: %w: %s", dataset, err, strings.TrimSpace(stderr))
	}
	return nil
}

// ErrKeyInUse reports that a key could not be unloaded because the
// encryptionroot still has mounted datasets under it.
var ErrKeyInUse = fmt.Errorf("encryption key is still in use by a mounted dataset")

func isKeyInUse(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "busy") || strings.Contains(s, "in use")
}

// KeyStatus reports whether the dataset's key is currently loaded.
func (m *Manager) KeyStatus(ctx context.Context, dataset string) (KeyStatus, error) {
	if err := validateDataset(dataset); err != nil {
		return "", err
	}
	stdout, stderr, err := m.run.Run(ctx, nil, "get", "-H", "-o", "value", "keystatus", dataset)
	if err != nil {
		return "", fmt.Errorf("read keystatus for %s: %w: %s", dataset, err, strings.TrimSpace(stderr))
	}
	switch v := strings.TrimSpace(stdout); v {
	case string(KeyAvailable):
		return KeyAvailable, nil
	case string(KeyUnavailable):
		return KeyUnavailable, nil
	case "", "-":
		// An unencrypted dataset reports "-". Treated as an error
		// rather than as "unavailable": the caller asked about an
		// encrypted dataset and got one that is not, which means the
		// two sides disagree about what this container is.
		return "", fmt.Errorf("dataset %s is not encrypted (keystatus %q)", dataset, v)
	default:
		return "", fmt.Errorf("unexpected keystatus %q for %s", v, dataset)
	}
}

// EncryptionRoot returns the dataset whose key covers this one. Two
// containers belonging to the same tenant share an encryptionroot; two
// tenants never do, which is the property the isolation claim rests on.
func (m *Manager) EncryptionRoot(ctx context.Context, dataset string) (string, error) {
	if err := validateDataset(dataset); err != nil {
		return "", err
	}
	stdout, stderr, err := m.run.Run(ctx, nil, "get", "-H", "-o", "value", "encryptionroot", dataset)
	if err != nil {
		return "", fmt.Errorf("read encryptionroot for %s: %w: %s", dataset, err, strings.TrimSpace(stderr))
	}
	root := strings.TrimSpace(stdout)
	if root == "" || root == "-" {
		return "", fmt.Errorf("dataset %s has no encryptionroot (it is not encrypted)", dataset)
	}
	return root, nil
}

// Exists reports whether a dataset is present.
func (m *Manager) Exists(ctx context.Context, dataset string) (bool, error) {
	if err := validateDataset(dataset); err != nil {
		return false, err
	}
	_, stderr, err := m.run.Run(ctx, nil, "list", "-H", "-o", "name", dataset)
	if err != nil {
		if strings.Contains(strings.ToLower(stderr), "does not exist") {
			return false, nil
		}
		return false, fmt.Errorf("list dataset %s: %w: %s", dataset, err, strings.TrimSpace(stderr))
	}
	return true, nil
}

// Destroy removes a dataset. Used to clean up a half-built container so
// a failed encrypted create leaves no partial state behind.
func (m *Manager) Destroy(ctx context.Context, dataset string) error {
	if err := validateDataset(dataset); err != nil {
		return err
	}
	_, stderr, err := m.run.Run(ctx, nil, "destroy", dataset)
	if err != nil {
		return fmt.Errorf("destroy dataset %s: %w: %s", dataset, err, strings.TrimSpace(stderr))
	}
	return nil
}
