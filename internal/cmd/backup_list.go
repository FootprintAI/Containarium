package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

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

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tUSER\tDATABASE\tCREATED\tSIZE\tDEST\tLOCATION")
	for _, r := range records {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Id, r.Username, r.Database, r.CreatedAt, humanBytes(r.SizeBytes), destLabel(r.Destination), r.Location)
	}
	return w.Flush()
}
