package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Back up and restore the databases inside containers (off-host)",
	Long: `Create, list, restore, and delete logical (pg_dump) backups of the
databases running inside Containarium containers. Backups are stored off
the database host — in a host backup directory (local) or a GCS bucket
(gcs) — so a dump never shares a failure domain with the data it
protects. See docs/DB-BACKUP-OPERATIONS.md for the operator runbook and
the ISO 27001 A.8.13 control mapping.

  containarium backup create alice --database app --dest gcs --gcs-bucket gs://my-backups/pg --server <host>
  containarium backup list alice --server <host>
  containarium backup restore alice-app-20260605T130405Z --clean --server <host>
  containarium backup delete alice-app-20260605T130405Z --server <host>`,
}

func init() {
	rootCmd.AddCommand(backupCmd)
}

// backupAPI is the subset of the typed client used by backup commands.
// Both the gRPC and HTTP clients satisfy it, so commands dispatch on
// --http without duplicating method calls.
type backupAPI interface {
	CreateBackup(req *pb.CreateBackupRequest) (*pb.CreateBackupResponse, error)
	ListBackups(username string) ([]*pb.BackupRecord, error)
	GetBackup(id string) (*pb.BackupRecord, error)
	RestoreBackup(req *pb.RestoreBackupRequest) (*pb.RestoreBackupResponse, error)
	DeleteBackup(id string) (*pb.DeleteBackupResponse, error)
	Close() error
}

func newBackupClient() (backupAPI, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required")
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

// parseDestination maps the --dest flag to the proto enum.
func parseDestination(s string) (pb.BackupDestination, error) {
	switch s {
	case "local":
		return pb.BackupDestination_BACKUP_DESTINATION_LOCAL, nil
	case "gcs":
		return pb.BackupDestination_BACKUP_DESTINATION_GCS, nil
	default:
		return pb.BackupDestination_BACKUP_DESTINATION_UNSPECIFIED,
			fmt.Errorf("invalid --dest %q (expected 'local' or 'gcs')", s)
	}
}

// destLabel renders a destination enum for human output.
func destLabel(d pb.BackupDestination) string {
	switch d {
	case pb.BackupDestination_BACKUP_DESTINATION_LOCAL:
		return "local"
	case pb.BackupDestination_BACKUP_DESTINATION_GCS:
		return "gcs"
	default:
		return "unspecified"
	}
}
