//go:build !windows

package container

import (
	"fmt"
	"strings"
)

// OwnerSyncResult summarizes a jump-server owner-account sync pass.
//
// NoKey and Failed are deliberately distinct: a container with no extractable
// SSH key is BENIGN (control-plane / CI / workspace containers legitimately
// carry no tenant authorized_keys), whereas Failed is the actionable case — a
// key was found but the host account could not be (re)created. Callers should
// fail-close (non-zero exit, alert) only on Failed, never on NoKey. See #1010.
type OwnerSyncResult struct {
	// Restored is the usernames whose host account was (re)created — or, in a
	// dry run, would be.
	Restored []string
	// Skipped counts containers whose account already exists (and force is
	// off), plus containers whose name doesn't follow the "<user>-container"
	// convention.
	Skipped int
	// NoKey is the usernames whose container had no extractable SSH key
	// (missing/unreadable authorized_keys). Benign — not a failure.
	NoKey []string
	// Failed is the usernames where a key WAS found but CreateJumpServerAccount
	// failed — the only genuinely actionable failure.
	Failed []string
}

// SyncOwnerAccounts restores host jump-server accounts for every persisted
// container whose account is missing, by extracting each container's SSH key
// and (re)creating the matching host user.
//
// It exists for spot-instance boot-disk loss recovery: the containers persist
// on the ZFS pool, but the recreated VM's /etc/passwd is empty, leaving the
// running containers SSH-dark until their host accounts are re-provisioned.
// The daemon runs this on startup (best-effort) so recovery is automatic
// rather than a manual `sync-accounts` step; the CLI uses it too.
//
// force recreates even when the account already exists; dryRun reports what
// would change without touching the host.
func (m *Manager) SyncOwnerAccounts(force, dryRun, verbose bool) (OwnerSyncResult, error) {
	var res OwnerSyncResult

	containers, err := m.List()
	if err != nil {
		return res, fmt.Errorf("list containers: %w", err)
	}

	for _, c := range containers {
		// Container names follow "<username>-container"; anything else isn't a
		// tenant box we own an account for.
		username := strings.TrimSuffix(c.Name, "-container")
		if username == c.Name {
			res.Skipped++
			continue
		}

		if !force && UserExists(username) {
			res.Skipped++
			continue
		}

		sshKey, err := m.ExtractSSHKey(c.Name, username, verbose)
		if err != nil || sshKey == "" {
			// No tenant key in the container — benign (infra/CP/workspace
			// boxes). Record separately so callers don't fail-close on it.
			res.NoKey = append(res.NoKey, username)
			continue
		}

		if dryRun {
			res.Restored = append(res.Restored, username)
			continue
		}

		if err := CreateJumpServerAccount(username, sshKey, verbose); err != nil {
			res.Failed = append(res.Failed, username)
			continue
		}
		res.Restored = append(res.Restored, username)
	}

	return res, nil
}
