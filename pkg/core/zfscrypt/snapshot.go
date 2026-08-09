package zfscrypt

import (
	"context"
	"fmt"
	"strings"
)

// Snapshot operations under encryption (#1202).
//
// The design's resolved decision #3: snapshot CREATION is allowed while the
// key is unavailable, and the inspection-time read is what fails. Blocking
// creation on key custody would let a transient KMS outage silently suppress
// a backup window — losing the backup is worse than having one that cannot
// be read until custody recovers.
//
// That split rests on a claim about ZFS: snapshots of an encrypted dataset
// can be taken, listed and destroyed with the key unloaded, because those
// operate on metadata rather than on the encrypted contents. It is verified
// against a real pool in zfscrypt_integration_test.go rather than assumed.

// ErrKeyUnavailableForInspection reports that a snapshot exists but cannot
// be read because its dataset's key is not loaded.
//
// A distinct error because the caller's remedy is specific and the raw ZFS
// message is not: the snapshot is intact, nothing is lost, and the fix is to
// restore key custody and retry (#1202 AC2).
var ErrKeyUnavailableForInspection = fmt.Errorf("snapshot contents cannot be read: the dataset's encryption key is not loaded")

// validateSnapshotName rejects names that would change which object a
// command acts on. `@` in particular would turn one snapshot reference into
// another.
func validateSnapshotName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("snapshot name is required")
	case strings.HasPrefix(name, "-"):
		return fmt.Errorf("invalid snapshot name %q: leading dash would be read as a flag", name)
	case strings.ContainsAny(name, " \t\n\r@/"):
		return fmt.Errorf("invalid snapshot name %q: must not contain whitespace, '@' or '/'", name)
	}
	return nil
}

// Snapshot creates <dataset>@<name> and returns the full snapshot name.
//
// Deliberately does NOT require the key. See the package-level note above:
// a backup that cannot be read yet beats no backup at all.
func (m *Manager) Snapshot(ctx context.Context, dataset, name string) (string, error) {
	if err := validateDataset(dataset); err != nil {
		return "", err
	}
	if err := validateSnapshotName(name); err != nil {
		return "", err
	}

	full := dataset + "@" + name
	_, stderr, err := m.run.Run(ctx, nil, "snapshot", full)
	if err != nil {
		return "", fmt.Errorf("create snapshot %s: %w: %s", full, err, strings.TrimSpace(stderr))
	}
	return full, nil
}

// ListSnapshots returns the snapshots of a dataset, newest last.
//
// Works with the key unloaded: snapshot names are metadata, not contents.
func (m *Manager) ListSnapshots(ctx context.Context, dataset string) ([]string, error) {
	if err := validateDataset(dataset); err != nil {
		return nil, err
	}
	stdout, stderr, err := m.run.Run(ctx, nil,
		"list", "-H", "-t", "snapshot", "-o", "name", "-s", "creation", "-r", dataset)
	if err != nil {
		return nil, fmt.Errorf("list snapshots of %s: %w: %s", dataset, err, strings.TrimSpace(stderr))
	}

	var out []string
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

// DestroySnapshot removes a snapshot. Like creation, it does not need the
// key — retention must keep working while custody is down, or a KMS outage
// would silently become an unbounded-growth incident.
func (m *Manager) DestroySnapshot(ctx context.Context, snapshot string) error {
	dataset, _, ok := strings.Cut(snapshot, "@")
	if !ok {
		return fmt.Errorf("invalid snapshot reference %q: expected <dataset>@<name>", snapshot)
	}
	if err := validateDataset(dataset); err != nil {
		return err
	}
	if _, stderr, err := m.run.Run(ctx, nil, "destroy", snapshot); err != nil {
		return fmt.Errorf("destroy snapshot %s: %w: %s", snapshot, err, strings.TrimSpace(stderr))
	}
	return nil
}

// EnsureInspectable reports whether a snapshot's CONTENTS can be read,
// returning ErrKeyUnavailableForInspection when they cannot.
//
// Called before an inspection so the caller gets a specific, actionable
// error instead of whatever ZFS says when a read hits an unkeyed dataset —
// which reads like corruption and sends an operator hunting the wrong
// problem (#1202 AC2).
func (m *Manager) EnsureInspectable(ctx context.Context, snapshot string) error {
	dataset, _, ok := strings.Cut(snapshot, "@")
	if !ok {
		return fmt.Errorf("invalid snapshot reference %q: expected <dataset>@<name>", snapshot)
	}

	status, err := m.KeyStatus(ctx, dataset)
	if err != nil {
		return err
	}
	if status != KeyAvailable {
		return fmt.Errorf("%s: %w (dataset %s, keystatus %q)",
			snapshot, ErrKeyUnavailableForInspection, dataset, status)
	}
	return nil
}
