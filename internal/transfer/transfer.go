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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/footprintai/containarium/internal/config"
)

// ErrSentinelUnresolved is returned by resolve when no SSH endpoint could
// be determined — neither an explicit SentinelHost, the container's
// daemon-stamped ssh_host (tried by callers before reaching here), nor
// $CONTAINARIUM_SENTINEL_HOST. Callers (notably the MCP push/sync
// handlers) check this with errors.Is to attach surface-specific guidance
// instead of leaving the agent to chase the env var.
var ErrSentinelUnresolved = errors.New("sentinel host not set")

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
		o.SentinelHost = os.Getenv(config.EnvSentinelHost)
		if o.SentinelHost == "" {
			return fmt.Errorf("%w: the daemon reports the reachable SSH target in the "+
				"container's ssh_host (see `containarium get %s` / the get_container tool) — "+
				"pass it as --sentinel <host>, or set CONTAINARIUM_SENTINEL_HOST. "+
				"An empty ssh_host means a direct / no-sentinel deployment; reach the "+
				"container at its IP instead", ErrSentinelUnresolved, o.Username)
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
	// Expand a leading "~/" or bare "~" into /home/<Username>/. The remote
	// shell only expands `~` outside of quotes, but our remote scripts
	// shQuote every path → the tilde survives literally, and we end up
	// creating a directory called "~" in the user's cwd. Substitute here
	// so callers can write "~/work" and have it mean what they expect.
	switch {
	case o.RemotePath == "~":
		o.RemotePath = "/home/" + o.Username
	case strings.HasPrefix(o.RemotePath, "~/"):
		o.RemotePath = "/home/" + o.Username + "/" + strings.TrimPrefix(o.RemotePath, "~/")
	}
	return nil
}

// sshBaseArgs returns the constant prefix used by every ssh invocation in
// this package. Always uses IdentitiesOnly=yes to avoid the failtoban budget
// burn the demo flow uncovered (see PR #132). Host key checking uses
// accept-new (trust-on-first-use) against the default ~/.ssh/known_hosts,
// matching connectcore.BuildSSHArgs and internal/mcp/sshexec.go's
// tofuHostKeyCallback — the same pattern this codebase already uses for
// other automated/agent-driven SSH flows. A first connection to a host
// pins its key; a later mismatch (a real MITM, or a container recreated
// with a fresh host key) is rejected rather than silently trusted. On a
// legitimate recreate, the fix is the same one-line `ssh-keygen -R <host>`
// any SSH user already knows — not a reason to disable checking outright.
func (o *Options) sshBaseArgs() []string {
	return []string{
		"-i", o.KeyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "LogLevel=ERROR",
		"-o", "ConnectTimeout=15",
	}
}

// sshTarget returns the "<user>@<host>" target for ssh invocations.
func (o *Options) sshTarget() string {
	return o.Username + "@" + o.SentinelHost
}
