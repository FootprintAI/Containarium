package cmd

import (
	"github.com/spf13/cobra"
)

// collaboratorCmd represents the collaborator command
var collaboratorCmd = &cobra.Command{
	Use:   "collaborator",
	Short: "Manage container collaborators",
	Long: `Manage collaborators who can access a container.

Collaborators can SSH into a container via their own account and then
switch to the container owner's account using 'sudo su'. All sessions
are logged for auditing purposes.

Examples:
  # Add a collaborator to alice's container
  containarium collaborator add alice bob --ssh-key ~/.ssh/bob.pub

  # List collaborators for alice's container
  containarium collaborator list alice

  # Remove a collaborator from alice's container
  containarium collaborator remove alice bob`,
}

func init() {
	rootCmd.AddCommand(collaboratorCmd)
}
