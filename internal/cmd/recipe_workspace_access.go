package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var recipeWorkspaceAccessCmd = &cobra.Command{
	Use:   "workspace-access <name>",
	Short: "Print the zero-click access URL for an agent-workspace box",
	Long: `Print a zero-click bootstrap URL for an agent-workspace box.

The daemon reads the box's in-box auth token and returns a URL of the form
https://<box>-workspace.<domain>/__ws_login?t=<token>. Loading it sets the
in-box session cookie and redirects to the workspace UI, so the embedded
console panel authenticates without a sign-in prompt.

  containarium recipe workspace-access ws1 --server <host>`,
	Args: cobra.ExactArgs(1),
	RunE: runRecipeWorkspaceAccess,
}

func init() {
	recipeCmd.AddCommand(recipeWorkspaceAccessCmd)
}

func runRecipeWorkspaceAccess(cmd *cobra.Command, args []string) error {
	c, err := newRecipeClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	resp, err := c.GetWorkspaceAccess(args[0])
	if err != nil {
		return err
	}
	if resp.Url != "" {
		fmt.Println(resp.Url)
		return nil
	}
	fmt.Printf("token: %s\n", resp.Token)
	fmt.Println("(no workspace route found; expose container port 8080 to get a URL)")
	return nil
}
