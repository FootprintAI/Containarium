package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var snapshotCreateName string

var snapshotCreateCmd = &cobra.Command{
	Use:   "create <username>",
	Short: "Take a snapshot of a container's storage",
	Long: `Take a point-in-time ZFS snapshot of the container's dataset.

Instant and initially free: the snapshot shares every block with the live
dataset and only consumes space as the two diverge. Safe to take while the
container is running, and while its encryption key is unloaded.

  containarium snapshot create alice --name before-upgrade --server <host>`,
	Args: cobra.ExactArgs(1),
	RunE: runSnapshotCreate,
}

var snapshotListCmd = &cobra.Command{
	Use:   "list <username>",
	Short: "List a container's snapshots and what they cost",
	Long: `List the container's snapshots with the space each one holds.

USED is what deleting that snapshot would free — the number that matters,
because a forgotten snapshot pins disk that nothing else accounts for.
REFERENCED is the total data it points at, most of which is shared with the
live dataset and would not be freed.

  containarium snapshot list alice --server <host>`,
	Args: cobra.ExactArgs(1),
	RunE: runSnapshotList,
}

var snapshotDeleteCmd = &cobra.Command{
	Use:   "delete <username> <snapshot>",
	Short: "Delete a snapshot and reclaim its space",
	Long: `Destroy the named snapshot and report the space reclaimed.

  containarium snapshot delete alice before-upgrade --server <host>`,
	Args: cobra.ExactArgs(2),
	RunE: runSnapshotDelete,
}

func init() {
	snapshotCmd.AddCommand(snapshotCreateCmd, snapshotListCmd, snapshotDeleteCmd)
	snapshotCreateCmd.Flags().StringVar(&snapshotCreateName, "name", "",
		"snapshot name (required); no '/', '@' or whitespace")
}

func runSnapshotCreate(cmd *cobra.Command, args []string) error {
	if snapshotCreateName == "" {
		return fmt.Errorf("--name is required")
	}
	c, err := newSnapshotClientFn()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	resp, err := c.CreateContainerSnapshot(&pb.CreateContainerSnapshotRequest{
		Username: args[0],
		Name:     snapshotCreateName,
	})
	if err != nil {
		return err
	}

	fmt.Printf("✅ Snapshot %q created for %s\n", resp.GetSnapshot().GetName(), args[0])
	// Said on every create, because the word "snapshot" reliably gets heard as
	// "backup" and the difference only shows up on the day the pool is gone.
	fmt.Println("   Note: a snapshot lives in the same pool as the data it snapshots. " +
		"For an off-host copy use `containarium backup create`.")
	return nil
}

func runSnapshotList(cmd *cobra.Command, args []string) error {
	c, err := newSnapshotClientFn()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	resp, err := c.ListContainerSnapshots(&pb.ListContainerSnapshotsRequest{Username: args[0]})
	if err != nil {
		return err
	}
	if len(resp.GetSnapshots()) == 0 {
		fmt.Printf("No snapshots for %s\n", args[0])
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tUSED\tREFERENCED")
	var total int64
	for _, s := range resp.GetSnapshots() {
		total += s.GetUsedBytes()
		fmt.Fprintf(w, "%s\t%s\t%s\n", s.GetName(),
			humanBytes(s.GetUsedBytes()), humanBytes(s.GetReferencedBytes()))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Printf("\n%d snapshot(s), holding %s that deleting them would free\n",
		len(resp.GetSnapshots()), humanBytes(total))
	return nil
}

func runSnapshotDelete(cmd *cobra.Command, args []string) error {
	c, err := newSnapshotClientFn()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	resp, err := c.DeleteContainerSnapshot(&pb.DeleteContainerSnapshotRequest{
		Username: args[0],
		Name:     args[1],
	})
	if err != nil {
		return err
	}

	fmt.Printf("✅ Snapshot %q deleted, freeing %s\n", args[1], humanBytes(resp.GetFreedBytes()))
	return nil
}

var (
	snapshotRollbackForce        bool
	snapshotRollbackDestroyNewer bool
)

var snapshotRollbackCmd = &cobra.Command{
	Use:   "rollback <username> <snapshot>",
	Short: "Return a container's storage to the state captured by a snapshot",
	Long: `Discard everything written since the snapshot.

DESTRUCTIVE, and destructive twice over: every change made since the
snapshot is gone, and any snapshot taken AFTER the target has to be
destroyed too. Both are refused by default.

  --force          stop the container first (it is left stopped, because
                   the data underneath just changed)
  --destroy-newer  accept losing the restore points taken after the target

A container whose encryption key is unavailable is refused: the rollback
would succeed, but the result would be ciphertext the daemon cannot open.

  containarium snapshot rollback alice before-upgrade --force --server <host>`,
	Args: cobra.ExactArgs(2),
	RunE: runSnapshotRollback,
}

func init() {
	snapshotCmd.AddCommand(snapshotRollbackCmd)
	f := snapshotRollbackCmd.Flags()
	f.BoolVar(&snapshotRollbackForce, "force", false,
		"stop the container first if it is running (it is left stopped)")
	f.BoolVar(&snapshotRollbackDestroyNewer, "destroy-newer", false,
		"destroy snapshots taken after the target, which ZFS requires to roll back past them")
}

func runSnapshotRollback(cmd *cobra.Command, args []string) error {
	c, err := newSnapshotClientFn()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	resp, err := c.RollbackContainerSnapshot(&pb.RollbackContainerSnapshotRequest{
		Username:     args[0],
		Name:         args[1],
		Force:        snapshotRollbackForce,
		DestroyNewer: snapshotRollbackDestroyNewer,
	})
	if err != nil {
		return err
	}

	fmt.Printf("✅ %s rolled back to %q\n", args[0], args[1])
	if resp.GetContainerStopped() {
		fmt.Printf("   The container was stopped to do this and is still stopped — "+
			"start it with `containarium wake %s` when you have checked the data.\n", args[0])
	}
	// Named, not counted: these restore points no longer exist and nothing
	// else records which they were.
	if n := len(resp.GetDestroyedSnapshots()); n > 0 {
		fmt.Printf("   Destroyed %d newer snapshot(s): %s\n", n,
			strings.Join(resp.GetDestroyedSnapshots(), ", "))
	}
	return nil
}
