//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/naming"
	"github.com/spf13/cobra"
)

var auditNamesCmd = &cobra.Command{
	Use:   "names",
	Short: "List existing owner/collaborator names that break the container naming rule (read-only)",
	Long: `Report existing owner and collaborator names that contain the
"-container-" infix or end in "-container", and collaborator account names that
more than one owner/collaborator pair derives. Such names can collide with
another owner's box (#3630).

Read-only: it lists containers and collaborator rows and changes nothing.
Existing names are never renamed; only new names are rejected.

Run on the host that runs Incus and the collaborator database.`,
	Args: cobra.NoArgs,
	RunE: runAuditNames,
}

func init() {
	auditCmd.AddCommand(auditNamesCmd)
}

func runAuditNames(cmd *cobra.Command, _ []string) error {
	mgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}
	infos, err := mgr.List()
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}
	var owners []string
	for _, c := range infos {
		if owner, ok := strings.CutSuffix(c.Name, "-container"); ok {
			owners = append(owners, owner)
		}
	}

	var pairs []naming.CollaboratorPair
	store, err := collaborator.NewStore(context.Background(), getPostgresConnString())
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: collaborator database unavailable, auditing owners only: %v\n", err)
	} else {
		defer store.Close()
		all, err := store.ListAll(context.Background())
		if err != nil {
			return err
		}
		for _, c := range all {
			pairs = append(pairs, naming.CollaboratorPair{Owner: c.OwnerUsername, Collaborator: c.CollaboratorUsername})
		}
	}

	findings := naming.AuditNames(owners, pairs)
	if len(findings) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No colliding names found.")
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "KIND\tNAME\tREASON")
	for _, f := range findings {
		fmt.Fprintf(w, "%s\t%s\t%s\n", f.Kind, f.Name, f.Reason)
	}
	return w.Flush()
}
