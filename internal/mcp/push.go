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
	})
	if err != nil {
		return "", fmt.Errorf("push failed: %w", err)
	}

	previousNote := "first push"
	if res.PreviousHead != "" {
		previousNote = fmt.Sprintf("%s..%s", shortShaMCP(res.PreviousHead), shortShaMCP(res.NewHead))
	}
	out := fmt.Sprintf(
		"pushed %d commit(s) on branch %s (%s), bundle=%d bytes",
		res.Commits, res.Branch, previousNote, res.BundleBytes,
	)
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

// pickSentinel prefers an explicit "sentinel" arg, then falls back to the
// client's configured SentinelHost (which itself comes from
// CONTAINARIUM_SENTINEL_HOST). Returning "" lets transfer.Options.resolve
// fall back to the env var directly, which keeps the error message
// uniform across both code paths.
func pickSentinel(client *Client, args map[string]interface{}) string {
	if h := getStringArg(args, "sentinel", ""); h != "" {
		return h
	}
	if client != nil && client.SentinelHost != "" {
		return client.SentinelHost
	}
	return ""
}

func shortShaMCP(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}
