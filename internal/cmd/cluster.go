package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// Managed Kubernetes clusters (#1413): a platform-operated k3s control
// plane plus worker VMs in typed size classes. This CLI covers the
// lifecycle verbs; `cluster status` rendering (#1417) and node-size
// flags (#1414) arrive with their stories. gRPC-only (mirrors volume
// and other server-side verbs).

var clusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Manage tenant-facing managed Kubernetes clusters",
	Long: `Create and manage Kubernetes clusters whose control plane is operated
by the platform and whose worker nodes are Containarium VMs.

The cluster is recorded immediately and provisioned asynchronously;
'cluster get' shows the state, and 'cluster kubeconfig' works once the
cluster is READY.

  containarium cluster create demo --server <host>
  containarium cluster list --server <host>
  containarium cluster get demo --server <host>
  containarium cluster kubeconfig demo --server <host> > demo.kubeconfig
  containarium cluster delete demo --server <host>`,
}

var clusterOwner string

var clusterCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a managed cluster (platform preset node size classes)",
	Args:  cobra.ExactArgs(1),
	RunE:  runClusterCreate,
}

var clusterListCmd = &cobra.Command{
	Use:   "list",
	Short: "List managed clusters",
	Args:  cobra.NoArgs,
	RunE:  runClusterList,
}

var clusterGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Show one managed cluster",
	Args:  cobra.ExactArgs(1),
	RunE:  runClusterGet,
}

var clusterDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a managed cluster (all VMs and state)",
	Args:  cobra.ExactArgs(1),
	RunE:  runClusterDelete,
}

var clusterKubeconfigCmd = &cobra.Command{
	Use:   "kubeconfig <name>",
	Short: "Print a READY cluster's admin kubeconfig to stdout",
	Args:  cobra.ExactArgs(1),
	RunE:  runClusterKubeconfig,
}

func init() {
	rootCmd.AddCommand(clusterCmd)
	clusterCmd.AddCommand(clusterCreateCmd, clusterListCmd, clusterGetCmd, clusterDeleteCmd, clusterKubeconfigCmd)
	clusterCmd.PersistentFlags().StringVar(&clusterOwner, "owner", "", "owning tenant (admin only; default: the authenticated user)")
}

func newClusterGRPCClient() (*client.GRPCClient, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required")
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

func printCluster(c *pb.Cluster) {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "Name:\t%s\n", c.Name)
	fmt.Fprintf(w, "Owner:\t%s\n", c.Owner)
	fmt.Fprintf(w, "State:\t%s\n", clusterStateString(c.State))
	if c.StateReason != "" {
		fmt.Fprintf(w, "Reason:\t%s\n", c.StateReason)
	}
	if c.K3SVersion != "" {
		fmt.Fprintf(w, "K3s:\t%s\n", c.K3SVersion)
	}
	if c.ApiEndpoint != "" {
		fmt.Fprintf(w, "API endpoint:\t%s\n", c.ApiEndpoint)
	}
	fmt.Fprintln(w, "Node groups:")
	for _, g := range c.NodeGroups {
		fmt.Fprintf(w, "  %s:\tcpu=%s memory=%s disk=%s nodes=%d..%d\n",
			g.Name, g.Size.Cpu, g.Size.Memory, g.Size.Disk, g.MinNodes, g.MaxNodes)
	}
	_ = w.Flush()
}

func clusterStateString(s pb.ClusterState) string {
	switch s {
	case pb.ClusterState_CLUSTER_STATE_PROVISIONING:
		return "provisioning"
	case pb.ClusterState_CLUSTER_STATE_READY:
		return "ready"
	case pb.ClusterState_CLUSTER_STATE_DEGRADED:
		return "degraded"
	case pb.ClusterState_CLUSTER_STATE_DELETING:
		return "deleting"
	case pb.ClusterState_CLUSTER_STATE_ERROR:
		return "error"
	default:
		return "unknown"
	}
}

func runClusterCreate(cmd *cobra.Command, args []string) error {
	c, err := newClusterGRPCClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	resp, err := c.CreateCluster(&pb.CreateClusterRequest{Name: args[0], Owner: clusterOwner})
	if err != nil {
		return err
	}
	fmt.Println(resp.Message)
	printCluster(resp.Cluster)
	return nil
}

func runClusterList(cmd *cobra.Command, args []string) error {
	c, err := newClusterGRPCClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	resp, err := c.ListClusters(clusterOwner)
	if err != nil {
		return err
	}
	if len(resp.Clusters) == 0 {
		fmt.Println("No clusters.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tOWNER\tSTATE\tGROUPS\tAPI ENDPOINT")
	for _, cl := range resp.Clusters {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
			cl.Name, cl.Owner, clusterStateString(cl.State), len(cl.NodeGroups), cl.ApiEndpoint)
	}
	return w.Flush()
}

func runClusterGet(cmd *cobra.Command, args []string) error {
	c, err := newClusterGRPCClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	resp, err := c.GetCluster(args[0], clusterOwner)
	if err != nil {
		return err
	}
	printCluster(resp.Cluster)
	return nil
}

func runClusterDelete(cmd *cobra.Command, args []string) error {
	c, err := newClusterGRPCClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	resp, err := c.DeleteCluster(args[0], clusterOwner)
	if err != nil {
		return err
	}
	fmt.Println(resp.Message)
	return nil
}

func runClusterKubeconfig(cmd *cobra.Command, args []string) error {
	c, err := newClusterGRPCClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	resp, err := c.GetClusterKubeconfig(args[0], clusterOwner)
	if err != nil {
		return err
	}
	// Bare kubeconfig on stdout so `> demo.kubeconfig` and
	// `KUBECONFIG=<(...)` both work; the notice goes to stderr.
	fmt.Print(resp.Kubeconfig)
	fmt.Fprintln(os.Stderr, "kubeconfig fetched; treat it as a credential")
	return nil
}
