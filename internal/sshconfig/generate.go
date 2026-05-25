// Package sshconfig generates a self-contained OpenSSH config file for
// every container the user can reach. The file is meant to be Include'd
// from ~/.ssh/config — the user adds one line once, and we never touch
// their primary config:
//
//	Include ~/.containarium/ssh_config
//
// After that, `ssh <container-name>` and `scp <container-name>:...` work
// without any further setup.
package sshconfig

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// Options controls how Host blocks are rendered. The two routing modes
// reflect the two ways a Containarium container is reachable:
//
//  1. Direct (Sentinel == ""): user is on the same network as the
//     container; the Host block uses the container's IP directly. This
//     is the local-Incus / dev workstation case.
//  2. Via sentinel: every connection goes to the sentinel's SSH port
//     and sshpiper routes by username to the right backend. The Host
//     block sets HostName=<sentinel> and User=<container-name>.
type Options struct {
	// Sentinel is the public-facing SSH endpoint, e.g.
	// "<cluster>.example.com" or "sentinel.example.com:22". Empty
	// means generate direct entries against each container's IP.
	Sentinel string
	// SentinelPort is the SSH port on the sentinel. Default 22.
	SentinelPort int
	// IdentityFile, if non-empty, is rendered as IdentityFile in every
	// Host block. Leave empty to let the user manage keys via the
	// agent / global config.
	IdentityFile string
	// User overrides the per-Host User. If empty: when Sentinel is set,
	// User=container-name (sshpiper routes); otherwise User="ubuntu".
	User string
	// IncludeStopped emits Host blocks for stopped containers too. Off
	// by default — if the container can't accept connections, an entry
	// just produces confusing timeouts.
	IncludeStopped bool
}

// Generated is the rendered config plus metadata for the caller (the CLI
// uses Count / SkippedNoAddr in user-facing output).
type Generated struct {
	Content        string
	Count          int
	SkippedNoAddr  int
	SkippedStopped int
}

// Header / footer markers delimit the section we own. If anyone ever
// needs to merge into an existing file, scanning between these is the
// supported way to find our block. Keep them stable.
const (
	beginMarker = "# >>> containarium ssh-config (managed) >>>"
	endMarker   = "# <<< containarium ssh-config (managed) <<<"
)

// Generate renders a self-contained ssh_config from the given containers.
// The output always includes the begin/end markers so callers writing
// into a larger file can locate and replace just our block.
func Generate(containers []incus.ContainerInfo, opts Options) Generated {
	if opts.SentinelPort == 0 {
		opts.SentinelPort = 22
	}

	var b strings.Builder
	g := Generated{}

	fmt.Fprintln(&b, beginMarker)
	fmt.Fprintf(&b, "# generated %s by `containarium ssh-config sync`\n",
		time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintln(&b, "# do not edit by hand — re-run sync to update")
	fmt.Fprintln(&b)

	// Sort by name so the file is stable across runs (avoids spurious
	// diffs in users who track this file in dotfiles).
	sorted := make([]incus.ContainerInfo, len(containers))
	copy(sorted, containers)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	for _, c := range sorted {
		if !opts.IncludeStopped && c.State != "Running" {
			g.SkippedStopped++
			continue
		}
		if opts.Sentinel == "" && c.IPAddress == "" {
			g.SkippedNoAddr++
			continue
		}
		writeHost(&b, c, opts)
		g.Count++
	}

	fmt.Fprintln(&b, endMarker)
	g.Content = b.String()
	return g
}

func writeHost(b *strings.Builder, c incus.ContainerInfo, opts Options) {
	fmt.Fprintf(b, "Host %s\n", c.Name)

	if opts.Sentinel != "" {
		host, port := splitHostPort(opts.Sentinel, opts.SentinelPort)
		fmt.Fprintf(b, "    HostName %s\n", host)
		fmt.Fprintf(b, "    Port %d\n", port)
		user := opts.User
		if user == "" {
			user = c.Name
		}
		fmt.Fprintf(b, "    User %s\n", user)
	} else {
		fmt.Fprintf(b, "    HostName %s\n", c.IPAddress)
		fmt.Fprintf(b, "    Port 22\n")
		user := opts.User
		if user == "" {
			user = "ubuntu"
		}
		fmt.Fprintf(b, "    User %s\n", user)
	}

	if opts.IdentityFile != "" {
		fmt.Fprintf(b, "    IdentityFile %s\n", opts.IdentityFile)
		// IdentitiesOnly prevents ssh-agent from trying every key it
		// holds before the right one — useful when the user has many
		// keys loaded and wants the file's identity to win.
		fmt.Fprintln(b, "    IdentitiesOnly yes")
	}

	if c.BackendID != "" {
		fmt.Fprintf(b, "    # backend: %s\n", c.BackendID)
	}
	fmt.Fprintln(b)
}

// splitHostPort accepts "host", "host:port", or "[ipv6]:port" and returns
// the host and a port (falling back to the default if not specified).
func splitHostPort(s string, defaultPort int) (string, int) {
	if strings.HasPrefix(s, "[") {
		if idx := strings.LastIndex(s, "]:"); idx > 0 {
			var port int
			fmt.Sscanf(s[idx+2:], "%d", &port)
			if port > 0 {
				return s[1:idx], port
			}
		}
		return strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"), defaultPort
	}
	if idx := strings.LastIndex(s, ":"); idx > 0 && !strings.Contains(s, "::") {
		var port int
		fmt.Sscanf(s[idx+1:], "%d", &port)
		if port > 0 {
			return s[:idx], port
		}
	}
	return s, defaultPort
}
