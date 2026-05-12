package cmd

import (
	"fmt"
	"os"

	"github.com/footprintai/containarium/internal/transfer"
	"github.com/spf13/cobra"
)

var (
	syncUser         string
	syncRemotePath   string
	syncSentinelHost string
	syncKeyPath      string
	syncDelete       bool
	syncExcludes     []string
	syncVerbose      bool
)

var syncCmd = &cobra.Command{
	Use:   "sync <username> [local-path]",
	Short: "Mirror a local directory into a container (rsync-style)",
	Long: `Mirror a local directory into a container, including uncommitted
changes, untracked files, and the entire .git/ history. Ships only the
content-hash delta on subsequent calls.

This is the "make the remote look like local right now" mode. Use
` + "`containarium push`" + ` instead when you want commit-only semantics.

Excluded by default (substring match): node_modules/, .terraform/,
__pycache__/, .pytest_cache/, .venv/, venv/, .DS_Store, .idea/, .vscode/.

By default, files that exist on the remote but not locally are LEFT in
place. Pass --delete to remove them.

Examples:
  # Mirror cwd to the container's default ~/work
  containarium sync demo-blog

  # Mirror with deletion (true rsync --delete semantics)
  containarium sync demo-blog --delete

  # Mirror a different local directory to a custom remote path
  containarium sync demo-blog /path/to/local --remote-path /srv/app

  # Add custom excludes on top of the defaults
  containarium sync demo-blog --exclude target/ --exclude dist/`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runSync,
}

func init() {
	rootCmd.AddCommand(syncCmd)
	syncCmd.Flags().StringVar(&syncRemotePath, "remote-path", "", "Destination directory inside the container (default: ~/work)")
	syncCmd.Flags().StringVar(&syncSentinelHost, "sentinel", "", "Sentinel SSH host (default: $CONTAINARIUM_SENTINEL_HOST)")
	syncCmd.Flags().StringVar(&syncKeyPath, "key", "", "SSH key path (default: ~/.containarium/keys/<username>)")
	syncCmd.Flags().BoolVar(&syncDelete, "delete", false, "Remove remote files that don't exist locally (rsync --delete)")
	syncCmd.Flags().StringSliceVar(&syncExcludes, "exclude", nil, "Additional exclude patterns (substring match)")
	syncCmd.Flags().BoolVarP(&syncVerbose, "verbose", "v", false, "Verbose progress on stderr")
}

func runSync(cmd *cobra.Command, args []string) error {
	syncUser = args[0]
	localPath := ""
	if len(args) > 1 {
		localPath = args[1]
	}

	// Apply user --exclude on top of the defaults (don't replace).
	excludes := append([]string{}, transfer.DefaultSyncExcludes...)
	excludes = append(excludes, syncExcludes...)

	res, err := transfer.Sync(transfer.SyncOptions{
		Options: transfer.Options{
			Username:     syncUser,
			SentinelHost: syncSentinelHost,
			KeyPath:      syncKeyPath,
			LocalPath:    localPath,
			RemotePath:   syncRemotePath,
			Verbose:      syncVerbose,
		},
		Delete:   syncDelete,
		Excludes: excludes,
	})
	if err != nil {
		return err
	}

	if res.Added == 0 && res.Modified == 0 && res.Deleted == 0 {
		fmt.Fprintln(os.Stdout, "sync: no changes")
		return nil
	}
	fmt.Fprintf(os.Stdout, "sync: +%d -%d ~%d files, %d bytes shipped\n",
		res.Added, res.Deleted, res.Modified, res.Bytes)
	return nil
}
