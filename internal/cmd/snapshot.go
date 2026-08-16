package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// Container snapshots (#1160).
//
// A ZFS snapshot of a container's dataset: instant, space-efficient, and
// takeable while the container runs. It is NOT a backup — it shares blocks
// with the live dataset and dies with the pool. `containarium backup` is the
// off-host one; this is the cheap rollback point you take before an upgrade.

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Take, list, and delete point-in-time snapshots of a container's storage",
	Long: `Manage ZFS snapshots of a container's dataset.

A snapshot is instant and initially free — it shares every block with the
live dataset and only starts consuming space as the two diverge. Take one
before an upgrade or a risky change; it is the cheapest rollback point
available.

A snapshot is NOT a backup. It lives in the same pool as the data it
snapshots, so it survives a bad "rm -rf" and not a lost disk. For off-host
copies see ` + "`containarium backup`" + `.

Snapshots work on encrypted containers with the key unloaded: ZFS allows it,
and refusing would mean a key-custody outage silently stopped your backup
window. Reading a snapshot back does need the key.

  containarium snapshot create alice --name before-upgrade --server <host>
  containarium snapshot list alice --server <host>
  containarium snapshot delete alice before-upgrade --server <host>`,
}

func init() {
	rootCmd.AddCommand(snapshotCmd)
}

// snapshotAPI is the subset of the typed client the snapshot commands use.
// Both the gRPC and HTTP clients satisfy it, so the commands dispatch on
// --http without duplicating call sites.
type snapshotAPI interface {
	CreateContainerSnapshot(req *pb.CreateContainerSnapshotRequest) (*pb.CreateContainerSnapshotResponse, error)
	ListContainerSnapshots(req *pb.ListContainerSnapshotsRequest) (*pb.ListContainerSnapshotsResponse, error)
	DeleteContainerSnapshot(req *pb.DeleteContainerSnapshotRequest) (*pb.DeleteContainerSnapshotResponse, error)
	Close() error
}

// newSnapshotClientFn is the seam tests substitute to exercise output and
// exit-code handling without a live daemon.
var newSnapshotClientFn = newSnapshotClient

func newSnapshotClient() (snapshotAPI, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required")
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}
