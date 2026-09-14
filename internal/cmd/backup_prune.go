package cmd

import (
	"fmt"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var (
	backupPruneDatabase string
	backupPruneKeep     int32
)

var backupPruneCmd = &cobra.Command{
	Use:   "prune <username>",
	Short: "Delete older backups, keeping only the newest N per database",
	Long: `Delete older backup records for a tenant, keeping the newest --keep per
database (or per hook label, for a --hook backup, which fills the same
slot). One database's history never counts against another's: omit
--database to prune every database this tenant has backups for, each
independently down to --keep.

This is the missing half of a scheduled backup (#1831, #1836): a
scheduler that only ever creates and never prunes will fill the backup
directory or object-store bucket without bound. Run this on whatever
cadence you like — the same cadence as backup create, or slower — it
doesn't need to be coupled to it.

A record whose delete fails (e.g. a transient object-store error) is
reported, not fatal: everything else that should be pruned still is.

Examples:
  containarium backup prune alice --database app --keep 7 --server <host>
  containarium backup prune alice --keep 3 --server <host>   # every database, keep 3 each`,
	Args: cobra.ExactArgs(1),
	RunE: runBackupPrune,
}

func init() {
	backupCmd.AddCommand(backupPruneCmd)
	f := backupPruneCmd.Flags()
	f.StringVar(&backupPruneDatabase, "database", "", "prune only this database (or hook label); omit to prune every database this tenant has backups for")
	f.Int32Var(&backupPruneKeep, "keep", 0, "number of newest backups to keep per database (required, must be >= 1)")
	_ = backupPruneCmd.MarkFlagRequired("keep")
}

func runBackupPrune(cmd *cobra.Command, args []string) error {
	username := args[0]
	if backupPruneKeep < 1 {
		return fmt.Errorf("--keep must be at least 1 (got %d); use 'backup delete <id>' to remove a specific backup", backupPruneKeep)
	}

	c, err := newBackupClientFn()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	if backupPruneDatabase == "" {
		fmt.Printf("Pruning %s, keeping the newest %d per database...\n", username, backupPruneKeep)
	} else {
		fmt.Printf("Pruning %s database %q, keeping the newest %d...\n", username, backupPruneDatabase, backupPruneKeep)
	}
	resp, err := c.PruneBackups(&pb.PruneBackupsRequest{
		Username: username,
		Database: backupPruneDatabase,
		Keep:     backupPruneKeep,
	})
	if err != nil {
		return err
	}

	fmt.Printf("\n✓ %s\n", resp.Message)
	for _, id := range resp.DeletedIds {
		fmt.Printf("  - deleted %s\n", id)
	}
	for _, f := range resp.Failures {
		fmt.Printf("  ✗ %s\n", f)
	}
	return nil
}
