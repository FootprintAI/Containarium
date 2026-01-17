package cmd

import (
	"github.com/spf13/cobra"
)

// appCmd represents the app command
var appCmd = &cobra.Command{
	Use:   "app",
	Short: "Manage deployed applications",
	Long: `Manage deployed applications in Containarium.

Applications are deployed to user containers and are accessible via HTTPS subdomains.

Examples:
  # Deploy an app from current directory
  containarium app deploy myapp --source .

  # List all apps
  containarium app list

  # Get app details
  containarium app get myapp

  # View app logs
  containarium app logs myapp

  # Stop/start/restart an app
  containarium app stop myapp
  containarium app start myapp
  containarium app restart myapp

  # Delete an app
  containarium app delete myapp`,
}

func init() {
	rootCmd.AddCommand(appCmd)
}
