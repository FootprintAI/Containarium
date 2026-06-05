package mcp

import (
	"fmt"

	"github.com/footprintai/containarium/internal/transfer"
)

// handlePush is the agent-native version of `containarium push <user>`.
// Same Go function (transfer.Push) backs both surfaces; this just adapts
// the MCP args dict into a typed PushOptions struct.
func handlePush(client *Client, args map[string]interface{}) (string, error) {
	username := getStringArg(args, "username", "")
	if username == "" {
		return "", fmt.Errorf("username is required")
	}

	res, err := transfer.Push(transfer.PushOptions{
		Options: transfer.Options{
			Username:     username,
			SentinelHost: pickSentinel(client, args),
			KeyPath:      getStringArg(args, "key_path", ""),
			LocalPath:    getStringArg(args, "local_path", ""),
			RemotePath:   getStringArg(args, "remote_path", ""),
			Verbose:      false,
		},
		Branch:     getStringArg(args, "branch", ""),
		IncludeWIP: getBoolArg(args, "include_wip", false),
		DeployCmd:  getStringArg(args, "deploy_cmd", ""),
		RemoteName: getStringArg(args, "remote_name", ""),
	})
	if err != nil {
		return "", fmt.Errorf("push failed: %w", err)
	}

	var out string
	if res.PreviousHead == "" {
		out = fmt.Sprintf("pushed branch %s to %s (first push, head=%s)",
			res.Branch, res.RemoteURL, shortShaMCP(res.NewHead))
	} else {
		out = fmt.Sprintf("pushed branch %s: %s..%s -> %s",
			res.Branch, shortShaMCP(res.PreviousHead), shortShaMCP(res.NewHead), res.RemoteURL)
	}
	if res.DeployCmd != "" {
		out += fmt.Sprintf("\ndeploy hook configured: %s", res.DeployCmd)
	}
	if res.WIPCommitMade {
		out += "\nWIP commit was shipped and the local repo was rewound to its pre-WIP state."
	}
	return out, nil
}

// handleSync is the agent-native version of `containarium sync <user>`.
func handleSync(client *Client, args map[string]interface{}) (string, error) {
	username := getStringArg(args, "username", "")
	if username == "" {
		return "", fmt.Errorf("username is required")
	}

	excludes := append([]string{}, transfer.DefaultSyncExcludes...)
	if extra, ok := args["exclude"].([]interface{}); ok {
		for _, e := range extra {
			if s, ok := e.(string); ok && s != "" {
				excludes = append(excludes, s)
			}
		}
	}

	res, err := transfer.Sync(transfer.SyncOptions{
		Options: transfer.Options{
			Username:     username,
			SentinelHost: pickSentinel(client, args),
			KeyPath:      getStringArg(args, "key_path", ""),
			LocalPath:    getStringArg(args, "local_path", ""),
			RemotePath:   getStringArg(args, "remote_path", ""),
			Verbose:      false,
		},
		Delete:   getBoolArg(args, "delete", false),
		Excludes: excludes,
	})
	if err != nil {
		return "", fmt.Errorf("sync failed: %w", err)
	}

	if res.Added == 0 && res.Modified == 0 && res.Deleted == 0 {
		return "sync: no changes (remote already matches local)", nil
	}
	return fmt.Sprintf(
		"sync: +%d added, ~%d modified, -%d deleted, %d bytes shipped",
		res.Added, res.Modified, res.Deleted, res.Bytes,
	), nil
}

// pickSentinel prefers an explicit "sentinel" arg, then the target
// container's daemon-stamped ssh_host — the sentinel it actually belongs
// to. Returning "" (a direct / no-sentinel deployment, or a lookup miss)
// lets transfer.Options.resolve surface the uniform "pass --sentinel" error.
func pickSentinel(client *Client, args map[string]interface{}) string {
	if h := getStringArg(args, "sentinel", ""); h != "" {
		return h
	}
	if client != nil {
		if u := getStringArg(args, "username", ""); u != "" {
			if resp, err := client.GetContainer(u); err == nil && resp.Container.SSHHost != "" {
				return resp.Container.SSHHost
			}
		}
	}
	return ""
}

func shortShaMCP(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}
