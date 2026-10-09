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
  containarium backup verify alice-app-20260605T130405Z --target scratch --server <host>
  containarium backup delete alice-app-20260605T130405Z --server <host>
  containarium backup prune alice --database app --keep 7 --server <host>`,
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
	VerifyBackup(req *pb.VerifyBackupRequest) (*pb.VerifyBackupResponse, error)
	DeleteBackup(id string) (*pb.DeleteBackupResponse, error)
	PruneBackups(req *pb.PruneBackupsRequest) (*pb.PruneBackupsResponse, error)
	Close() error
}

// newBackupClientFn is the seam tests substitute to exercise a backup
// command's output and exit-code handling without a live daemon.
var newBackupClientFn = newBackupClient

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
// engineLabel renders the engine the way it read before it became an enum
// (#1157). The wire value is now BACKUP_ENGINE_POSTGRES; a human running
// `backup get` should still see "postgres".
func engineLabel(e pb.BackupEngine) string {
	switch e {
	case pb.BackupEngine_BACKUP_ENGINE_POSTGRES:
		return "postgres"
	case pb.BackupEngine_BACKUP_ENGINE_HOOK:
		return "hook"
	default:
		// Covers a record written before the enum existed, and one whose
		// engine this build does not know. Both are genuinely unknown to
		// the reader, and saying so beats naming an engine on a guess.
		return "unspecified"
	}
}

// parseKeyMode maps the --key-mode flag to the typed enum (#2402). Empty
// is UNSPECIFIED: the daemon's default, never a client-side guess.
func parseKeyMode(s string) (pb.BackupKeyMode, error) {
	switch s {
	case "":
		return pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED, nil
	case "age-recipient":
		return pb.BackupKeyMode_BACKUP_KEY_MODE_AGE_RECIPIENT, nil
	case "managed":
		return pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED, nil
	case "both":
		return pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH, nil
	default:
		return pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED,
			fmt.Errorf("invalid --key-mode %q (expected 'age-recipient', 'managed' or 'both')", s)
	}
}

// keyModeLabel renders a key mode for human output, in the --key-mode
// vocabulary so what `backup get` shows is what `backup create` takes.
func keyModeLabel(m pb.BackupKeyMode) string {
	switch m {
	case pb.BackupKeyMode_BACKUP_KEY_MODE_AGE_RECIPIENT:
		return "age-recipient"
	case pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED:
		return "managed"
	case pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH:
		return "both"
	default:
		return "unspecified"
	}
}

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
