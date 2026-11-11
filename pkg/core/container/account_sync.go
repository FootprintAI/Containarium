//go:build !windows

package container

import (
	"context"
	"errors"
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
	// Partial is the usernames whose account was created but where at least
	// one ADDITIONAL key could not be authorized. Not a failure (the box is
	// reachable) but not a clean restore either, so it is neither hidden in
	// Restored nor escalated into Failed.
	Partial []string
	// KeysRestored maps username -> how many authorized keys were installed on
	// the host account. Surfaced so the caller can PRINT the count: a box whose
	// container holds three keys coming back with one is the #1477 failure, and
	// it is otherwise invisible until someone's login is refused.
	KeysRestored map[string]int
	// RevokedDropped maps username -> how many keys in the box were skipped
	// because the registry marks them revoked (#3395).
	RevokedDropped map[string]int
	// AllRevoked is the usernames whose every box key is revoked: no account
	// is restored for them. Not a failure; the keys are meant to be dead.
	AllRevoked []string
	// FilterErr is the first error the KeyFilter returned (e.g. the key
	// registry is unreachable). Those boxes are in Failed and get no account.
	FilterErr error
}

// KeyFilter drops keys that must not seed a host account, returning the kept
// keys and how many were dropped. A non-nil error means the filter could not
// decide (the registry is down); the caller must then restore nothing.
//
// It is injected rather than imported because the registry lives in
// internal/sshauthz, which already imports this package.
type KeyFilter func(ctx context.Context, keys []string) (kept []string, dropped int, err error)

// OwnerSyncOptions configures a sync pass.
//
// A struct rather than a fourth positional bool: the call sites already read
// `SyncOwnerAccounts(false, false, false)`, which is unreadable at a glance and
// silently wrong if two flags are transposed.
type OwnerSyncOptions struct {
	// Force recreates accounts that already exist.
	Force bool
	// DryRun reports what would change without touching the host.
	DryRun bool
	// Verbose prints per-container progress.
	Verbose bool
	// OnlyUser limits the sweep to a single container's account. Empty means
	// every container on the host — which is the destructive-sounding default
	// an operator should be told about, hence the flag (#1478).
	OnlyUser string
	// KeyFilter is REQUIRED: it removes keys the ssh_keys registry marks
	// revoked before an account is seeded from the box's authorized_keys
	// (#3395; revoking never edits the box's own file). A nil filter makes
	// SyncOwnerAccounts fail closed with an error.
	KeyFilter KeyFilter
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
// Options are described on OwnerSyncOptions.
func (m *Manager) SyncOwnerAccounts(opts OwnerSyncOptions) (OwnerSyncResult, error) {
	res := OwnerSyncResult{KeysRestored: map[string]int{}, RevokedDropped: map[string]int{}}
	if opts.KeyFilter == nil {
		return res, errors.New("owner account sync needs a revocation KeyFilter; refusing to seed accounts from unfiltered box keys")
	}

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

		// Scope to one box when asked. Counted as skipped rather than ignored
		// so the caller can tell "no such container" from "nothing to do".
		if opts.OnlyUser != "" && username != opts.OnlyUser {
			res.Skipped++
			continue
		}

		if !opts.Force && UserExists(username) {
			res.Skipped++
			continue
		}

		sshKeys, err := m.ExtractSSHKeys(c.Name, username, opts.Verbose)
		if err != nil || len(sshKeys) == 0 {
			// No tenant key in the container — benign (infra/CP/workspace
			// boxes). Record separately so callers don't fail-close on it.
			res.NoKey = append(res.NoKey, username)
			continue
		}

		// Drop keys revoked since they were written into the box. Fail closed:
		// a filter error means no account for this box, never an unfiltered one.
		sshKeys, dropped, ferr := opts.KeyFilter(context.Background(), sshKeys)
		if ferr != nil {
			if res.FilterErr == nil {
				res.FilterErr = ferr
			}
			res.Failed = append(res.Failed, username)
			continue
		}
		if dropped > 0 {
			res.RevokedDropped[username] = dropped
		}
		if len(sshKeys) == 0 {
			res.AllRevoked = append(res.AllRevoked, username)
			continue
		}

		if opts.DryRun {
			res.Restored = append(res.Restored, username)
			res.KeysRestored[username] = len(sshKeys)
			continue
		}

		// Seed the account with the first key, then authorize the rest —
		// the same shape the create path (manager.go) and the collaborator
		// path use. Recovery previously stopped at the seed, which is what
		// made it revoke every other key on the box (#1477).
		if err := createJumpServerAccountFn(username, sshKeys[0], opts.Verbose); err != nil {
			res.Failed = append(res.Failed, username)
			continue
		}
		installed := 1
		authorizedAll := true
		for _, k := range sshKeys[1:] {
			if err := addAuthorizedKeyFn(username, k); err != nil {
				// The account exists and at least one key works, so this is
				// NOT a failed restore — but it is a partial one, and saying
				// so is the entire point of the fix. Report it and keep going
				// rather than abandoning the remaining keys.
				authorizedAll = false
				if opts.Verbose {
					fmt.Printf("       ! could not authorize an additional key for %s: %v\n", username, err)
				}
				continue
			}
			installed++
		}
		if !authorizedAll {
			res.Partial = append(res.Partial, username)
		}
		res.Restored = append(res.Restored, username)
		res.KeysRestored[username] = installed
	}

	return res, nil
}
