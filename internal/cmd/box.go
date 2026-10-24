package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// `containarium box delete` (the noun-verb form of `delete`). It is a second
// way to reach the same code, with a guard the older command does not have:
// it refuses unless --yes is given, because deleting a box removes the
// container and its disk. `containarium delete` is unchanged, so existing
// scripts keep working.

var (
	boxDeleteYes   bool
	boxDeleteForce bool

	// boxDeleteFn is the delete itself; a var so a test can observe that a
	// refused call never reaches it.
	boxDeleteFn = deleteBox
)

var boxCmd = &cobra.Command{
	Use:   "box",
	Short: "Manage boxes (noun-verb form)",
	Long: `Manage boxes. Today this holds one subcommand, 'delete'; the older
'containarium delete' still works and behaves as before.`,
}

var boxDeleteCmd = &cobra.Command{
	Use:   "delete <username>",
	Short: "Delete a box and its disk (requires --yes)",
	Long: `Delete a user's box: the LXC container and its disk. This cannot be undone.

Unlike 'containarium delete', this refuses to run without --yes, so a typo or a
pasted command cannot delete anything by accident. The box must be stopped
unless --force is given.

Examples:
  # Delete a stopped box
  containarium box delete alice --yes

  # Delete a running box
  containarium box delete bob --yes --force`,
	Args: cobra.ExactArgs(1),
	RunE: runBoxDelete,
}

func init() {
	rootCmd.AddCommand(boxCmd)
	boxCmd.AddCommand(boxDeleteCmd)

	boxDeleteCmd.Flags().BoolVar(&boxDeleteYes, "yes", false, "Confirm that the box and its disk are deleted permanently (required)")
	boxDeleteCmd.Flags().BoolVarP(&boxDeleteForce, "force", "f", false, "Delete even if the box is running")
}

func runBoxDelete(cmd *cobra.Command, args []string) error {
	username := args[0]
	if !boxDeleteYes {
		return fmt.Errorf("refusing to delete box %q without --yes (this permanently deletes the container and its disk)", username+"-container")
	}
	return boxDeleteFn(username, boxDeleteForce)
}
