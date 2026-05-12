// Package transfer ships files from the local workstation into a remote
// Containarium container, via the same SSH path the demo flow uses
// (laptop → sentinel → sshpiper → backend → containarium-shell → incus exec).
//
// Two entry-points serving two mental models:
//
//   - Push: ships committed git history via `git bundle`. Atomic per
//     commit. Refuses dirty working trees unless IncludeWIP is set.
//
//   - Sync: mirrors the working directory (including .git/) via a manual
//     content-hash diff + tar of changed files. Pushes uncommitted +
//     untracked + stash refs alongside committed history. Delta-only on
//     subsequent calls.
//
// Both use one-shot ssh-with-command invocations rather than bidirectional
// protocols (git-receive-pack, rsync --server) — those are fragile through
// our shell stack.
package transfer

import (
	"fmt"
	"os"
	"path/filepath"
)

// Options carries the inputs both Push and Sync need.
type Options struct {
	// Username — the container's user. Maps to the ssh user the
	// sentinel routes through sshpiper.
	Username string

	// SentinelHost — the public SSH endpoint, e.g. "34.42.156.100" or
	// "sentinel.example.com". When empty, transfer looks up
	// $CONTAINARIUM_SENTINEL_HOST.
	SentinelHost string

	// KeyPath — path to the SSH private key for Username. When empty,
	// defaults to ~/.containarium/keys/<Username>.
	KeyPath string

	// LocalPath — local file or directory being shipped. For Push,
	// must be a git repo (or contain one at LocalPath/.git). Defaults
	// to the caller's cwd when empty.
	LocalPath string

	// RemotePath — destination inside the container. Defaults to
	// "/home/<Username>/work" when empty. The directory is created on
	// first call.
	RemotePath string

	// Verbose toggles progress logging on stderr.
	Verbose bool
}

// resolve fills in the inferred-default fields and validates required ones.
func (o *Options) resolve() error {
	if o.Username == "" {
		return fmt.Errorf("username is required")
	}
	if o.SentinelHost == "" {
		o.SentinelHost = os.Getenv("CONTAINARIUM_SENTINEL_HOST")
		if o.SentinelHost == "" {
			return fmt.Errorf("sentinel host not set: pass --sentinel or set CONTAINARIUM_SENTINEL_HOST")
		}
	}
	if o.KeyPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home dir: %w", err)
		}
		o.KeyPath = filepath.Join(home, ".containarium", "keys", o.Username)
	}
	if _, err := os.Stat(o.KeyPath); err != nil {
		return fmt.Errorf("ssh key not readable at %s: %w (was the container created with this user?)", o.KeyPath, err)
	}
	if o.LocalPath == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve cwd: %w", err)
		}
		o.LocalPath = cwd
	}
	abs, err := filepath.Abs(o.LocalPath)
	if err != nil {
		return fmt.Errorf("absolute path for local: %w", err)
	}
	o.LocalPath = abs
	if _, err := os.Stat(o.LocalPath); err != nil {
		return fmt.Errorf("local path: %w", err)
	}
	if o.RemotePath == "" {
		o.RemotePath = "/home/" + o.Username + "/work"
	}
	return nil
}

// sshBaseArgs returns the constant prefix used by every ssh invocation in
// this package. Always uses IdentitiesOnly=yes to avoid the failtoban budget
// burn the demo flow uncovered (see PR #132). Strict host key checking is
// disabled because container-side host keys regenerate on every recreate.
func (o *Options) sshBaseArgs() []string {
	return []string{
		"-i", o.KeyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-o", "ConnectTimeout=15",
	}
}

// sshTarget returns the "<user>@<host>" target for ssh invocations.
func (o *Options) sshTarget() string {
	return o.Username + "@" + o.SentinelHost
}
