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
func handleSyncSSHConfig(client *Client, args map[string]interface{}) (string, error) {
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

	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", filepath.Dir(out), err)
	}
	// 0600 — the file lists every host the user can SSH to. Sensitive
	// in the same sense their ssh_config is.
	if err := os.WriteFile(out, []byte(gen.Content), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", out, err)
	}

	result := fmt.Sprintf(
		"✅ Wrote %s\n   %d host(s) generated, %d skipped (stopped), %d skipped (no address)\n",
		out, gen.Count, gen.SkippedStopped, gen.SkippedNoAddr,
	)
	result += "\nIf this is the first run, add one line to your ~/.ssh/config:\n"
	result += fmt.Sprintf("    Include %s\n", out)
	result += "\nThen `ssh <container-name>` reaches the container."
	return result, nil
}

// fetchContainersForSSHConfig pulls the container list via the MCP
// client and translates from mcp.Container to incus.ContainerInfo —
// the shape the shared sshconfig generator expects. Same logic the
// CLI uses; just a different list source.
func fetchContainersForSSHConfig(client *Client) ([]incus.ContainerInfo, error) {
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
