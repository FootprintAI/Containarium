package cmd

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var backupListCmd = &cobra.Command{
	Use:   "list [username]",
	Short: "List stored backups (newest first)",
	Long: `List stored backup records. With no username, admins see all
tenants' backups; a non-admin token sees only its own.

Examples:
  containarium backup list --server <host>
  containarium backup list alice --server <host>`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBackupList,
}

func init() {
	backupCmd.AddCommand(backupListCmd)
}

func runBackupList(cmd *cobra.Command, args []string) error {
	var username string
	if len(args) == 1 {
		username = args[0]
	}

	c, err := newBackupClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	records, err := c.ListBackups(username)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Println("No backups found.")
		return nil
	}

	return printBackupList(os.Stdout, records)
}

// printBackupList renders the list table. The ID stays the first column:
// scripts/restore-tenant.sh reads it with awk '{print $1}'.
func printBackupList(out io.Writer, records []*pb.BackupRecord) error {
	w := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tUSER\tDATABASE\tCREATED\tSIZE\tDEST\tENCRYPTED\tVERIFIED\tLOCATION")
	for _, r := range records {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Id, r.Username, r.Database, r.CreatedAt, humanBytes(r.SizeBytes),
			destLabel(r.Destination), encryptedLabel(r), verifiedLabel(r.LastVerification), r.Location)
	}
	return w.Flush()
}

// encryptedLabel renders whether the stored bytes are ciphertext (#3169).
// Plaintext is upper-case for the same reason "never" is spelled out under
// VERIFIED: it is the state an operator most needs to notice.
func encryptedLabel(r *pb.BackupRecord) string {
	if r.Encrypted {
		return "yes"
	}
	return "NO"
}

// verifiedLabel renders last-verified state for the list view. An
// unverified backup says so plainly rather than showing a blank cell —
// "never" is the state an operator most needs to notice.
func verifiedLabel(v *pb.BackupVerification) string {
	if v == nil {
		return "never"
	}
	switch v.Result {
	case pb.VerificationResult_VERIFICATION_RESULT_PASSED:
		return "pass " + v.VerifiedAt
	case pb.VerificationResult_VERIFICATION_RESULT_FAILED:
		return "FAIL " + v.VerifiedAt
	default:
		return "unknown"
	}
}
