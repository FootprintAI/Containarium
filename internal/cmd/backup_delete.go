package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var backupDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a stored dump and its index entry",
	Long: `Delete a stored dump (and its metadata sidecar). Retention policy is
the caller's responsibility — wire this into a cron job that prunes
backups older than your retention window. See docs/DB-BACKUP-OPERATIONS.md.`,
	Args: cobra.ExactArgs(1),
	RunE: runBackupDelete,
}

func init() {
	backupCmd.AddCommand(backupDeleteCmd)
}

func runBackupDelete(cmd *cobra.Command, args []string) error {
	c, err := newBackupClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	resp, err := c.DeleteBackup(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s\n", resp.Message)
	return nil
}
