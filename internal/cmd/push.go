package cmd

import (
	"fmt"
	"os"

	"github.com/footprintai/containarium/internal/transfer"
	"github.com/spf13/cobra"
)

var (
	pushUser         string
	pushBranch       string
	pushRemotePath   string
	pushSentinelHost string
	pushKeyPath      string
	pushIncludeWIP   bool
	pushVerbose      bool
)

var pushCmd = &cobra.Command{
	Use:   "push <username> [local-path]",
	Short: "Push committed git history into a container",
	Long: `Push committed git history into a container via the existing SSH path
(laptop -> sentinel -> sshpiper -> container).

Ships only the delta since the last push to this container, using
'git bundle' as the wire format. The local working tree must be clean
unless --include-wip is set, in which case uncommitted + untracked
changes are wrapped in a WIP commit and the local repo is rewound
after the push.

For mirror-semantics (uncommitted changes carried over as working-tree
state, not as a commit), use ` + "`containarium sync`" + ` instead.

Examples:
  # Push current branch from cwd to the container's default ~/work
  containarium push demo-blog

  # Push a specific branch with WIP autocommit-and-rewind
  containarium push demo-blog --branch feature/foo --include-wip

  # Push from a different local repo to a custom remote path
  containarium push demo-blog /path/to/local --remote-path /srv/app`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runPush,
}

func init() {
	rootCmd.AddCommand(pushCmd)
	pushCmd.Flags().StringVar(&pushBranch, "branch", "", "Git branch to push (default: current HEAD branch)")
	pushCmd.Flags().StringVar(&pushRemotePath, "remote-path", "", "Destination directory inside the container (default: ~/work)")
	pushCmd.Flags().StringVar(&pushSentinelHost, "sentinel", "", "Sentinel SSH host (default: $CONTAINARIUM_SENTINEL_HOST)")
	pushCmd.Flags().StringVar(&pushKeyPath, "key", "", "SSH key path (default: ~/.containarium/keys/<username>)")
	pushCmd.Flags().BoolVar(&pushIncludeWIP, "include-wip", false, "Auto-commit uncommitted changes as a WIP commit and rewind after push")
	pushCmd.Flags().BoolVarP(&pushVerbose, "verbose", "v", false, "Verbose progress on stderr")
}

func runPush(cmd *cobra.Command, args []string) error {
	pushUser = args[0]
	localPath := ""
	if len(args) > 1 {
		localPath = args[1]
	}

	res, err := transfer.Push(transfer.PushOptions{
		Options: transfer.Options{
			Username:     pushUser,
			SentinelHost: pushSentinelHost,
			KeyPath:      pushKeyPath,
			LocalPath:    localPath,
			RemotePath:   pushRemotePath,
			Verbose:      pushVerbose,
		},
		Branch:     pushBranch,
		IncludeWIP: pushIncludeWIP,
	})
	if err != nil {
		return err
	}

	previousNote := "first push"
	if res.PreviousHead != "" {
		previousNote = fmt.Sprintf("%s..%s", shortSha(res.PreviousHead), shortSha(res.NewHead))
	} else {
		previousNote = fmt.Sprintf("first push to %s, head=%s", pushUser, shortSha(res.NewHead))
	}

	fmt.Fprintf(os.Stdout, "pushed %d commit(s) on branch %s (%s), bundle=%d bytes\n",
		res.Commits, res.Branch, previousNote, res.BundleBytes)
	if res.WIPCommitMade {
		fmt.Fprintln(os.Stdout, "  note: WIP commit shipped and local repo rewound to pre-WIP state")
	}
	return nil
}

func shortSha(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}
