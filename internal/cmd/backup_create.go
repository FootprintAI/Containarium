package cmd

import (
	"fmt"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var (
	backupCreateDatabase string
	backupCreateDest     string
	backupCreateBucket   string
	backupCreateDBUser   string
	backupCreateDBPass   string
	backupCreateDBHost   string
	backupCreateDBPort   int32
)

var backupCreateCmd = &cobra.Command{
	Use:   "create <username>",
	Short: "Dump a container's database and store it off-host",
	Long: `Run pg_dump inside the tenant's container and store the compressed
dump at the chosen destination.

Connection defaults target a per-container local Postgres on loopback
(user "postgres", host 127.0.0.1, port 5432). The password, if needed, is
passed to pg_dump via PGPASSWORD inside the container — never on argv.

Examples:
  containarium backup create alice --database app --dest local --server <host>
  containarium backup create alice --database app --dest gcs \
      --gcs-bucket gs://my-backups/pg --db-password "$PGPW" --server <host>`,
	Args: cobra.ExactArgs(1),
	RunE: runBackupCreate,
}

func init() {
	backupCmd.AddCommand(backupCreateCmd)
	f := backupCreateCmd.Flags()
	f.StringVar(&backupCreateDatabase, "database", "", "database name to dump (required)")
	f.StringVar(&backupCreateDest, "dest", "local", "destination: 'local' or 'gcs'")
	f.StringVar(&backupCreateBucket, "gcs-bucket", "", "GCS bucket/prefix for --dest gcs, e.g. gs://my-backups/pg")
	f.StringVar(&backupCreateDBUser, "db-user", "", "Postgres role (default: postgres)")
	f.StringVar(&backupCreateDBPass, "db-password", "", "Postgres password (omit for peer/trust auth)")
	f.StringVar(&backupCreateDBHost, "db-host", "", "DB host as seen inside the container (default: 127.0.0.1)")
	f.Int32Var(&backupCreateDBPort, "db-port", 0, "DB port (default: 5432)")
}

func runBackupCreate(cmd *cobra.Command, args []string) error {
	username := args[0]
	if backupCreateDatabase == "" {
		return fmt.Errorf("--database is required")
	}
	dest, err := parseDestination(backupCreateDest)
	if err != nil {
		return err
	}
	if dest == pb.BackupDestination_BACKUP_DESTINATION_GCS && backupCreateBucket == "" {
		return fmt.Errorf("--gcs-bucket is required when --dest gcs")
	}

	c, err := newBackupClient()
	if err != nil {
		return err
	}
	defer c.Close()

	fmt.Printf("Backing up %s database %q to %s...\n", username, backupCreateDatabase, backupCreateDest)
	resp, err := c.CreateBackup(&pb.CreateBackupRequest{
		Username:    username,
		Destination: dest,
		GcsBucket:   backupCreateBucket,
		Connection: &pb.PgConnection{
			Database: backupCreateDatabase,
			User:     backupCreateDBUser,
			Password: backupCreateDBPass,
			Host:     backupCreateDBHost,
			Port:     backupCreateDBPort,
		},
	})
	if err != nil {
		return err
	}

	fmt.Printf("\n✓ %s\n", resp.Message)
	if r := resp.Record; r != nil {
		fmt.Printf("  ID:       %s\n", r.Id)
		fmt.Printf("  Size:     %s\n", humanBytes(r.SizeBytes))
		fmt.Printf("  SHA-256:  %s\n", r.Sha256)
		fmt.Printf("  Location: %s\n", r.Location)
	}
	return nil
}

// humanBytes renders a byte count in a compact, human-readable form.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
