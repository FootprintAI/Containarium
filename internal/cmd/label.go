package cmd

import (
	"github.com/spf13/cobra"
)

// labelCmd represents the label command
var labelCmd = &cobra.Command{
	Use:   "label",
	Short: "Manage container labels",
	Long: `Manage Kubernetes-style labels on containers.

Labels are key-value pairs that can be used to organize and filter containers.
Labels are stored with the prefix "containarium.label." in the container config.

Examples:
  # Set labels on a container
  containarium label set alice team=backend project=api

  # Add a single label
  containarium label set alice env=production

  # List labels for a container
  containarium label list alice

  # Remove labels from a container
  containarium label remove alice env project

  # List containers filtered by label
  containarium list --label team=backend`,
}

func init() {
	rootCmd.AddCommand(labelCmd)
}
