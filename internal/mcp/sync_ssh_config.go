package mcp

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/footprintai/containarium/internal/sshconfig"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// handleSyncSSHConfig is the agent-native version of `containarium
// ssh-config sync`. It lets the agent wire SSH aliases without needing
// the CLI binary installed on the operator's machine. Same internal
// generator, different invocation surface — preserves the CLI-first
// principle (one Go function, two surfaces) from CLAUDE.md.
func handleSyncSSHConfig(client API, args map[string]interface{}) (string, error) {
	// Resolve output path. Default lives under $HOME so it works the
	// same way the CLI version does — both produce a file that the
	// user's ~/.ssh/config can Include.
	out := getStringArg(args, "out", "")
	if out == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		out = filepath.Join(home, ".containarium", "ssh_config")
	}

	containers, err := fetchContainersForSSHConfig(client)
	if err != nil {
		return "", err
	}

	opts := sshconfig.Options{
		Sentinel:       getStringArg(args, "sentinel", ""),
		IdentityFile:   getStringArg(args, "identity_file", ""),
		IncludeStopped: getBoolArg(args, "include_stopped", false),
	}
	gen := sshconfig.Generate(containers, opts)

	// Atomic, backed up, and refuses to replace a real config with a
	// zero-host generation — see sshconfig.WriteConfig. This surface is
	// where that guard matters most: an agent calling this tool has no
	// eye on the file, so a wipe caused by an expired credential would
	// pass unnoticed until someone's ssh aliases stopped resolving.
	backedUp, err := sshconfig.WriteConfig(out, gen, getBoolArg(args, "force", false))
	if err != nil {
		return "", err
	}

	// A zero-host run is reported as a warning, not a success tick — it
	// almost always means the caller could not see its boxes.
	mark := "✅ Wrote"
	if gen.Count == 0 {
		mark = "⚠️  Wrote (0 hosts — check your credential)"
	}
	result := fmt.Sprintf(
		"%s %s\n   %d host(s) generated, %d skipped (stopped), %d skipped (no address)\n",
		mark, out, gen.Count, gen.SkippedStopped, gen.SkippedNoAddr,
	)
	if backedUp {
		result += fmt.Sprintf("   previous config saved to %s.bak\n", out)
	}
	result += "\nIf this is the first run, add one line to your ~/.ssh/config:\n"
	result += fmt.Sprintf("    Include %s\n", out)
	result += "\nThen `ssh <container-name>` reaches the container."
	return result, nil
}

// fetchContainersForSSHConfig pulls the container list via the MCP
// client and translates from mcp.Container to incus.ContainerInfo —
// the shape the shared sshconfig generator expects. Same logic the
// CLI uses; just a different list source.
func fetchContainersForSSHConfig(client API) ([]incus.ContainerInfo, error) {
	resp, err := client.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	out := make([]incus.ContainerInfo, 0, len(resp.Containers))
	for _, c := range resp.Containers {
		info := incus.ContainerInfo{
			Name:  c.Name,
			State: c.State,
		}
		if c.Network != nil {
			info.IPAddress = c.Network.IPAddress
		}
		if c.Resources != nil {
			info.CPU = c.Resources.CPU
			info.Memory = c.Resources.Memory
			info.Disk = c.Resources.Disk
		}
		info.Labels = c.Labels
		out = append(out, info)
	}
	return out, nil
}
