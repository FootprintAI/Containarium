package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// Shared, multi-writer CephFS data volumes (#384). Capability-gated on the
// daemon: create/attach are rejected unless the backend has a cephfs pool.
// gRPC-only for now (mirrors other server-side verbs).

var volumeCmd = &cobra.Command{
	Use:   "volume",
	Short: "Manage shared, multi-writer (CephFS) data volumes",
	Long: `Create, list, attach, and detach CephFS custom volumes that can be
mounted read-write into multiple containers at once.

Only a CephFS-backed backend can serve these (CephFS coordinates concurrent
writers; a block device on ZFS/ext4 cannot). On a single-node ZFS host the
daemon reports the capability as unsupported and rejects create/attach.

  containarium volume list --server <host>
  containarium volume create dataset --size 50GB --server <host>
  containarium volume attach dataset alice --path /mnt/shared --server <host>
  containarium volume detach dataset alice --server <host>
  containarium volume delete dataset --server <host>`,
}

var (
	volumeSize     string
	volumePool     string
	volumeForce    bool
	volumePath     string
	volumeReadOnly bool
)

var volumeCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a shared CephFS volume with a quota",
	Args:  cobra.ExactArgs(1),
	RunE:  runVolumeCreate,
}

var volumeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List shared volumes (and whether this backend supports them)",
	Args:  cobra.NoArgs,
	RunE:  runVolumeList,
}

var volumeDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a shared volume (refuses while attached unless --force)",
	Args:  cobra.ExactArgs(1),
	RunE:  runVolumeDelete,
}

var volumeAttachCmd = &cobra.Command{
	Use:   "attach <volume> <container>",
	Short: "Mount a shared volume into a container (read-write by default)",
	Args:  cobra.ExactArgs(2),
	RunE:  runVolumeAttach,
}

var volumeDetachCmd = &cobra.Command{
	Use:   "detach <volume> <container>",
	Short: "Unmount a shared volume from a container",
	Args:  cobra.ExactArgs(2),
	RunE:  runVolumeDetach,
}

func init() {
	rootCmd.AddCommand(volumeCmd)
	volumeCmd.AddCommand(volumeCreateCmd, volumeListCmd, volumeDeleteCmd, volumeAttachCmd, volumeDetachCmd)

	volumeCreateCmd.Flags().StringVar(&volumeSize, "size", "", "volume quota, e.g. 50GB or 1TB (required)")
	volumeCreateCmd.Flags().StringVar(&volumePool, "pool", "", "CephFS pool (default: the backend's detected pool)")
	volumeListCmd.Flags().StringVar(&volumePool, "pool", "", "CephFS pool to list (default: detected)")
	volumeDeleteCmd.Flags().StringVar(&volumePool, "pool", "", "CephFS pool (default: detected)")
	volumeDeleteCmd.Flags().BoolVar(&volumeForce, "force", false, "delete even if still attached")
	volumeAttachCmd.Flags().StringVar(&volumePool, "pool", "", "CephFS pool (default: detected)")
	volumeAttachCmd.Flags().StringVar(&volumePath, "path", "", "mount path inside the container (required)")
	volumeAttachCmd.Flags().BoolVar(&volumeReadOnly, "read-only", false, "mount read-only")
}

// parseSizeBytes parses a human size like "50GB", "1TiB", "500M", or a
// bare byte count into bytes. KB/MB/GB/TB are decimal (1000-based);
// KiB/MiB/GiB/TiB are binary (1024-based); a bare K/M/G/T is treated as
// binary (the common shell expectation).
func parseSizeBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	upper := strings.ToUpper(s)
	type unit struct {
		suffix string
		mult   int64
	}
	// Order matters: check longer suffixes (KIB) before shorter (K/B).
	units := []unit{
		{"TIB", 1 << 40}, {"GIB", 1 << 30}, {"MIB", 1 << 20}, {"KIB", 1 << 10},
		{"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"KB", 1e3},
		{"T", 1 << 40}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}, {"B", 1},
	}
	for _, u := range units {
		if strings.HasSuffix(upper, u.suffix) {
			num := strings.TrimSpace(upper[:len(upper)-len(u.suffix)])
			f, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid size %q: %w", s, err)
			}
			return int64(f * float64(u.mult)), nil
		}
	}
	// Bare number → bytes.
	n, err := strconv.ParseInt(upper, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q (expected e.g. 50GB, 1TiB, or a byte count)", s)
	}
	return n, nil
}

// newVolumeGRPCClient returns a gRPC client; volume verbs are server-side.
func newVolumeGRPCClient() (*client.GRPCClient, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required")
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

func runVolumeCreate(cmd *cobra.Command, args []string) error {
	if volumeSize == "" {
		return fmt.Errorf("--size is required (e.g. --size 50GB)")
	}
	bytes, err := parseSizeBytes(volumeSize)
	if err != nil {
		return err
	}
	c, err := newVolumeGRPCClient()
	if err != nil {
		return err
	}
	defer c.Close()
	resp, err := c.CreateVolume(&pb.CreateVolumeRequest{Name: args[0], SizeBytes: bytes, Pool: volumePool})
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s\n", resp.Message)
	return nil
}

func runVolumeList(cmd *cobra.Command, args []string) error {
	c, err := newVolumeGRPCClient()
	if err != nil {
		return err
	}
	defer c.Close()
	resp, err := c.ListVolumes(volumePool)
	if err != nil {
		return err
	}
	if !resp.SharedVolumesSupported {
		fmt.Printf("Shared volumes not supported on this backend: %s\n", resp.CapabilityDetail)
		return nil
	}
	fmt.Printf("Shared volumes: supported (%s)\n", resp.CapabilityDetail)
	if len(resp.Volumes) == 0 {
		fmt.Println("No volumes.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tPOOL\tTYPE\tATTACHMENTS")
	for _, v := range resp.Volumes {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", v.Name, v.Pool, v.ContentType, len(v.Attachments))
	}
	return w.Flush()
}

func runVolumeDelete(cmd *cobra.Command, args []string) error {
	c, err := newVolumeGRPCClient()
	if err != nil {
		return err
	}
	defer c.Close()
	resp, err := c.DeleteVolume(args[0], volumePool, volumeForce)
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s\n", resp.Message)
	return nil
}

func runVolumeAttach(cmd *cobra.Command, args []string) error {
	if volumePath == "" {
		return fmt.Errorf("--path is required (mount path inside the container)")
	}
	c, err := newVolumeGRPCClient()
	if err != nil {
		return err
	}
	defer c.Close()
	resp, err := c.AttachVolume(&pb.AttachVolumeRequest{
		Volume:    args[0],
		Pool:      volumePool,
		Container: args[1],
		MountPath: volumePath,
		ReadOnly:  volumeReadOnly,
	})
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s\n", resp.Message)
	return nil
}

func runVolumeDetach(cmd *cobra.Command, args []string) error {
	c, err := newVolumeGRPCClient()
	if err != nil {
		return err
	}
	defer c.Close()
	resp, err := c.DetachVolume(args[0], args[1])
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s\n", resp.Message)
	return nil
}
