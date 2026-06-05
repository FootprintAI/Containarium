package cmd

import (
	"fmt"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var (
	backupRestoreClean    bool
	backupRestoreDatabase string
	backupRestoreDBUser   string
	backupRestoreDBPass   string
	backupRestoreDBHost   string
	backupRestoreDBPort   int32
)

var backupRestoreCmd = &cobra.Command{
	Use:   "restore <id>",
	Short: "Restore a stored dump back into its container's database",
	Long: `Stream a stored dump back into the owning tenant's container database
via pg_restore. The dump is integrity-checked (SHA-256) before it touches
the database.

DESTRUCTIVE with --clean: pg_restore is run with --clean --if-exists,
dropping objects before recreating them. Without --clean, restore loads
into the existing database and errors on conflicting objects.

By default the dump is restored into the database it was taken from;
override with --database to restore into a different one.

Examples:
  containarium backup restore alice-app-20260605T130405Z --clean --server <host>
  containarium backup restore alice-app-20260605T130405Z --database app_staging --server <host>`,
	Args: cobra.ExactArgs(1),
	RunE: runBackupRestore,
}

func init() {
	backupCmd.AddCommand(backupRestoreCmd)
	f := backupRestoreCmd.Flags()
	f.BoolVar(&backupRestoreClean, "clean", false, "pass --clean --if-exists to pg_restore (drops objects first)")
	f.StringVar(&backupRestoreDatabase, "database", "", "target database (default: the backup's own database)")
	f.StringVar(&backupRestoreDBUser, "db-user", "", "Postgres role (default: postgres)")
	f.StringVar(&backupRestoreDBPass, "db-password", "", "Postgres password (omit for peer/trust auth)")
	f.StringVar(&backupRestoreDBHost, "db-host", "", "DB host as seen inside the container (default: 127.0.0.1)")
	f.Int32Var(&backupRestoreDBPort, "db-port", 0, "DB port (default: 5432)")
}

func runBackupRestore(cmd *cobra.Command, args []string) error {
	c, err := newBackupClient()
	if err != nil {
		return err
	}
	defer c.Close()

	fmt.Printf("Restoring backup %q (clean=%t)...\n", args[0], backupRestoreClean)
	resp, err := c.RestoreBackup(&pb.RestoreBackupRequest{
		Id:    args[0],
		Clean: backupRestoreClean,
		Connection: &pb.PgConnection{
			Database: backupRestoreDatabase,
			User:     backupRestoreDBUser,
			Password: backupRestoreDBPass,
			Host:     backupRestoreDBHost,
			Port:     backupRestoreDBPort,
		},
	})
	if err != nil {
		return err
	}
	fmt.Printf("\n✓ %s\n", resp.Message)
	return nil
}
