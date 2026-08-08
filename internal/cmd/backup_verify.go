package cmd

import (
	"fmt"
	"os"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var (
	backupVerifyTarget string
	backupVerifyDBUser string
	backupVerifyDBPass string
	backupVerifyDBHost string
	backupVerifyDBPort int32
)

var backupVerifyCmd = &cobra.Command{
	Use:   "verify <id>",
	Short: "Restore-test a stored dump against a throwaway container",
	Long: `Prove a backup is restorable, not merely intact.

The recorded SHA-256 shows the dump bytes have not changed. It cannot show
the dump will load: a dump taken against a wedged database, a schema the
target engine cannot read, or a truncated export all hash perfectly well.
Verification answers the question the checksum cannot, by actually
restoring the dump.

The dump is loaded into a throwaway database inside the --target
container, sanity-checked, and the scratch database is dropped again. The
source container is never touched; verification refuses to run if --target
resolves to the container the backup came from.

A backup that fails to restore is reported as a FAILED verification with
the engine's own error — the command exits non-zero, so it can gate a
scheduled job. The outcome is recorded on the backup record, so
"last verified" survives the run and is retrievable as A.8.13 evidence.

Examples:
  containarium backup verify alice-app-20260605T130405Z --target scratch --server <host>
  containarium backup list alice --server <host>   # shows last-verified state`,
	Args: cobra.ExactArgs(1),
	RunE: runBackupVerify,
}

func init() {
	backupCmd.AddCommand(backupVerifyCmd)
	f := backupVerifyCmd.Flags()
	f.StringVar(&backupVerifyTarget, "target", "", "tenant whose container is used as the throwaway restore target (required)")
	f.StringVar(&backupVerifyDBUser, "db-user", "", "Postgres role on the target (default: postgres)")
	f.StringVar(&backupVerifyDBPass, "db-password", "", "Postgres password on the target (omit for peer/trust auth)")
	f.StringVar(&backupVerifyDBHost, "db-host", "", "DB host as seen inside the target container (default: 127.0.0.1)")
	f.Int32Var(&backupVerifyDBPort, "db-port", 0, "DB port on the target (default: 5432)")
	_ = backupVerifyCmd.MarkFlagRequired("target")
}

func runBackupVerify(cmd *cobra.Command, args []string) error {
	c, err := newBackupClientFn()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	fmt.Printf("Restore-testing backup %q against target %q...\n", args[0], backupVerifyTarget)
	resp, err := c.VerifyBackup(&pb.VerifyBackupRequest{
		Id:             args[0],
		TargetUsername: backupVerifyTarget,
		Connection: &pb.PgConnection{
			User:     backupVerifyDBUser,
			Password: backupVerifyDBPass,
			Host:     backupVerifyDBHost,
			Port:     backupVerifyDBPort,
		},
	})
	if err != nil {
		return err
	}

	v := resp.Verification
	if v == nil {
		return fmt.Errorf("daemon returned no verification result")
	}

	fmt.Println()
	for _, check := range v.Checks {
		mark := "✓"
		if !check.Passed {
			mark = "✗"
		}
		fmt.Printf("  %s %-18s %s\n", mark, check.Name, check.Detail)
	}
	fmt.Printf("\n  target:  %s (scratch db %s, dropped)\n", v.TargetContainer, v.ScratchDatabase)
	fmt.Printf("  when:    %s", v.VerifiedAt)
	if v.VerifiedBy != "" {
		fmt.Printf("  by %s", v.VerifiedBy)
	}
	fmt.Printf("\n  elapsed: %dms\n\n", v.DurationMs)

	// A failed restore test is a real answer, not a broken command — but
	// it must exit non-zero so a scheduled verification fails loudly
	// instead of scrolling past in a log.
	if v.Result != pb.VerificationResult_VERIFICATION_RESULT_PASSED {
		fmt.Fprintf(os.Stderr, "✗ %s\n", resp.Message)
		return errBackupVerificationFailed
	}
	fmt.Printf("✓ %s\n", resp.Message)
	return nil
}

// errBackupVerificationFailed marks a completed-but-failed restore test.
// Carried as a distinct value so the exit path is obvious at the call
// site; cobra prints it and main exits non-zero.
var errBackupVerificationFailed = fmt.Errorf("backup verification failed")
