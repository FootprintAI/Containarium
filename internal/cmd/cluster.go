package cmd

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/footprintai/containarium/internal/client"
	clusterstore "github.com/footprintai/containarium/internal/cluster"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// Managed Kubernetes clusters (#1413): a platform-operated k3s control
// plane plus worker VMs in typed size classes. This CLI covers the
// lifecycle verbs and node-pool editing; `cluster status` rendering
// (#1417) and node-size create flags (#1414) arrive with their
// stories. Dual transport like backup/agent/crew: gRPC by default,
// REST with --http (the token-authenticated path).

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

var (
	clusterOwner     string
	clusterNodesMin  int32
	clusterNodesMax  int32
	clusterIsolation isolationFlag
)

// isolationFlag is the enum-backed --isolation flag (#1428). Cobra
// rejects anything that is not a NodeIsolation value at parse time, so
// a typo is a CLI error rather than a request that silently falls back
// to the default class on the daemon.
type isolationFlag struct{ value pb.NodeIsolation }

func (f *isolationFlag) String() string { return nodeIsolationString(f.value) }

func (f *isolationFlag) Type() string { return "isolation" }

func (f *isolationFlag) Set(s string) error {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "vm":
		f.value = pb.NodeIsolation_NODE_ISOLATION_VM
	case "container":
		f.value = pb.NodeIsolation_NODE_ISOLATION_CONTAINER
	default:
		f.value = pb.NodeIsolation_NODE_ISOLATION_UNSPECIFIED
		return fmt.Errorf("invalid isolation %q (expected vm or container)", s)
	}
	return nil
}

// nodeIsolationString renders the class for humans. An unrecognized
// value reads as "unknown", never as "vm": a boundary the CLI cannot
// name must not look like the strong one.
func nodeIsolationString(i pb.NodeIsolation) string {
	switch i {
	case pb.NodeIsolation_NODE_ISOLATION_VM:
		return "vm"
	case pb.NodeIsolation_NODE_ISOLATION_CONTAINER:
		return "container"
	default:
		return "unknown"
	}
}

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

var (
	clusterGroups      []string
	clusterEventsLimit int32
)

var clusterStatusCmd = &cobra.Command{
	Use:   "status <name>",
	Short: "Show a cluster's nodes, per-group counts, and scale history",
	Args:  cobra.ExactArgs(1),
	RunE:  runClusterStatus,
}

var clusterNodePoolCmd = &cobra.Command{
	Use:   "node-pool <name>",
	Short: "Replace a cluster's node groups (size classes and min/max bounds)",
	Long: `Replace the cluster's node groups. Each --group is one size class as
key=value pairs; the set you pass REPLACES the current set.

  containarium cluster node-pool demo \
    --group name=small,cpu=2,memory=4GB,disk=40GB,min=1,max=5 \
    --group name=large,cpu=8,memory=16GB,disk=160GB,min=0,max=2`,
	Args: cobra.ExactArgs(1),
	RunE: runClusterNodePool,
}

func init() {
	rootCmd.AddCommand(clusterCmd)
	clusterCmd.AddCommand(clusterCreateCmd, clusterListCmd, clusterGetCmd, clusterDeleteCmd, clusterKubeconfigCmd, clusterNodePoolCmd, clusterStatusCmd)
	clusterStatusCmd.Flags().Int32Var(&clusterEventsLimit, "events", 10, "scale events to show, newest first")
	clusterCmd.PersistentFlags().StringVar(&clusterOwner, "owner", "", "owning tenant (admin only; default: the authenticated user)")
	clusterCreateCmd.Flags().Int32Var(&clusterNodesMin, "nodes-min", -1, "small size class's minimum worker count (default: platform preset)")
	clusterCreateCmd.Flags().Int32Var(&clusterNodesMax, "nodes-max", -1, "small size class's maximum worker count (default: platform preset)")
	clusterCreateCmd.Flags().Var(&clusterIsolation, "isolation",
		"node isolation class: vm (default) or container. Container nodes share the host kernel and are only "+
			"accepted where the operator has opted the host in; the daemon refuses them otherwise")
	clusterNodePoolCmd.Flags().StringArrayVar(&clusterGroups, "group", nil,
		"node group as name=<g>,cpu=<n>,memory=<x>GB,disk=<x>GB,min=<n>,max=<n> (repeatable, required)")
}

// clusterAPI is the transport-neutral surface the cluster verbs use;
// implemented by both the gRPC and the HTTP client.
type clusterAPI interface {
	CreateCluster(req *pb.CreateClusterRequest) (*pb.CreateClusterResponse, error)
	ListClusters(owner string) (*pb.ListClustersResponse, error)
	GetCluster(name, owner string) (*pb.GetClusterResponse, error)
	DeleteCluster(name, owner string) (*pb.DeleteClusterResponse, error)
	GetClusterKubeconfig(name, owner string) (*pb.GetClusterKubeconfigResponse, error)
	GetClusterStatus(name, owner string, eventsLimit int32) (*pb.GetClusterStatusResponse, error)
	UpdateClusterNodePool(req *pb.UpdateClusterNodePoolRequest) (*pb.UpdateClusterNodePoolResponse, error)
	Close() error
}

func newClusterClient() (clusterAPI, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required")
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

// createNodeGroups applies --nodes-min/--nodes-max to the platform
// presets' small class (other classes keep their preset bounds; use
// `cluster node-pool` for full control). Returns nil when neither flag
// is set, so the server applies its presets untouched.
func createNodeGroups(cmd *cobra.Command) ([]*pb.NodeGroup, error) {
	if !cmd.Flags().Changed("nodes-min") && !cmd.Flags().Changed("nodes-max") {
		return nil, nil
	}
	var out []*pb.NodeGroup
	for _, g := range clusterstore.DefaultNodeGroups() {
		g := g
		if g.Name == "small" {
			if cmd.Flags().Changed("nodes-min") {
				g.MinNodes = clusterNodesMin
			}
			if cmd.Flags().Changed("nodes-max") {
				g.MaxNodes = clusterNodesMax
			}
		}
		out = append(out, &pb.NodeGroup{
			Name:     g.Name,
			Size:     &pb.ResourceLimits{Cpu: g.Size.CPU, Memory: g.Size.Memory, Disk: g.Size.Disk},
			MinNodes: g.MinNodes,
			MaxNodes: g.MaxNodes,
		})
	}
	return out, nil
}

// parseNodeGroup parses one --group flag value into a typed NodeGroup.
func parseNodeGroup(spec string) (*pb.NodeGroup, error) {
	g := &pb.NodeGroup{Size: &pb.ResourceLimits{}}
	for _, kv := range strings.Split(spec, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			return nil, fmt.Errorf("--group %q: %q is not key=value", spec, kv)
		}
		switch k {
		case "name":
			g.Name = v
		case "cpu":
			g.Size.Cpu = v
		case "memory":
			g.Size.Memory = v
		case "disk":
			g.Size.Disk = v
		case "min":
			n, err := strconv.ParseInt(v, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("--group %q: min: %w", spec, err)
			}
			g.MinNodes = int32(n)
		case "max":
			n, err := strconv.ParseInt(v, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("--group %q: max: %w", spec, err)
			}
			g.MaxNodes = int32(n)
		default:
			return nil, fmt.Errorf("--group %q: unknown key %q (want name/cpu/memory/disk/min/max)", spec, k)
		}
	}
	return g, nil
}

func printCluster(c *pb.Cluster) { printClusterTo(os.Stdout, c) }

// printClusterTo renders one cluster's metadata. Used by `cluster get`
// and `cluster status`, so the isolation class shows up on every
// cluster read — "which clusters share a kernel with this host" is
// answerable without querying the daemon's config.
func printClusterTo(out io.Writer, c *pb.Cluster) {
	w := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "Name:\t%s\n", c.Name)
	fmt.Fprintf(w, "Owner:\t%s\n", c.Owner)
	fmt.Fprintf(w, "State:\t%s\n", clusterStateString(c.State))
	fmt.Fprintf(w, "Isolation:\t%s\n", nodeIsolationString(c.NodeIsolation))
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
	c, err := newClusterClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	req := &pb.CreateClusterRequest{
		Name: args[0], Owner: clusterOwner,
		// Unset stays UNSPECIFIED on the wire and resolves to VM
		// server-side — the CLI does not pick a class the caller
		// did not ask for.
		NodeIsolation: clusterIsolation.value,
	}
	if groups, gerr := createNodeGroups(cmd); gerr != nil {
		return gerr
	} else if groups != nil {
		req.NodeGroups = groups
	}
	resp, err := c.CreateCluster(req)
	if err != nil {
		return err
	}
	fmt.Println(resp.Message)
	printCluster(resp.Cluster)
	return nil
}

func runClusterList(cmd *cobra.Command, args []string) error {
	c, err := newClusterClient()
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
	return writeClusterList(os.Stdout, resp.Clusters)
}

// writeClusterList renders the `cluster list` table. ISOLATION is a
// first-class column, not a detail behind `cluster get`: an auditor
// scanning the fleet needs the weak-boundary clusters to stand out in
// the list itself.
func writeClusterList(out io.Writer, clusters []*pb.Cluster) error {
	w := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tOWNER\tSTATE\tISOLATION\tGROUPS\tAPI ENDPOINT")
	for _, cl := range clusters {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			cl.Name, cl.Owner, clusterStateString(cl.State), nodeIsolationString(cl.NodeIsolation),
			len(cl.NodeGroups), cl.ApiEndpoint)
	}
	return w.Flush()
}

func runClusterGet(cmd *cobra.Command, args []string) error {
	c, err := newClusterClient()
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
	c, err := newClusterClient()
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
	c, err := newClusterClient()
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

func runClusterNodePool(cmd *cobra.Command, args []string) error {
	if len(clusterGroups) == 0 {
		return fmt.Errorf("at least one --group is required (the set you pass replaces the current set)")
	}
	groups := make([]*pb.NodeGroup, 0, len(clusterGroups))
	for _, spec := range clusterGroups {
		g, err := parseNodeGroup(spec)
		if err != nil {
			return err
		}
		groups = append(groups, g)
	}
	c, err := newClusterClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	resp, err := c.UpdateClusterNodePool(&pb.UpdateClusterNodePoolRequest{
		Name: args[0], Owner: clusterOwner, NodeGroups: groups,
	})
	if err != nil {
		return err
	}
	fmt.Println(resp.Message)
	printCluster(resp.Cluster)
	return nil
}

func clusterNodeStateString(s pb.ClusterNodeState) string {
	switch s {
	case pb.ClusterNodeState_CLUSTER_NODE_STATE_PROVISIONING:
		return "provisioning"
	case pb.ClusterNodeState_CLUSTER_NODE_STATE_READY:
		return "ready"
	case pb.ClusterNodeState_CLUSTER_NODE_STATE_DRAINING:
		return "draining"
	default:
		return "unknown"
	}
}

func scaleEventKindString(k pb.ScaleEventKind) string {
	switch k {
	case pb.ScaleEventKind_SCALE_EVENT_KIND_SCALE_UP:
		return "scale-up"
	case pb.ScaleEventKind_SCALE_EVENT_KIND_SCALE_DOWN:
		return "scale-down"
	case pb.ScaleEventKind_SCALE_EVENT_KIND_REFUSED:
		return "REFUSED"
	case pb.ScaleEventKind_SCALE_EVENT_KIND_NODE_REPLACED:
		return "node-replaced"
	default:
		return "unknown"
	}
}

func runClusterStatus(cmd *cobra.Command, args []string) error {
	c, err := newClusterClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	st, err := c.GetClusterStatus(args[0], clusterOwner, clusterEventsLimit)
	if err != nil {
		return err
	}
	printCluster(st.Cluster)

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "\nGROUP\tSIZE\tNODES\tBOUNDS")
	for _, g := range st.Groups {
		fmt.Fprintf(w, "%s\tcpu=%s mem=%s disk=%s\t%d\t%d..%d\n",
			g.Group.Name, g.Group.Size.Cpu, g.Group.Size.Memory, g.Group.Size.Disk,
			g.CurrentNodes, g.Group.MinNodes, g.Group.MaxNodes)
	}
	if len(st.Nodes) > 0 {
		fmt.Fprintln(w, "\nNODE\tROLE\tGROUP\tSTATE")
		for _, n := range st.Nodes {
			role := "worker"
			if n.Role == pb.ClusterNodeRole_CLUSTER_NODE_ROLE_CONTROL_PLANE {
				role = "control-plane"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", n.VmName, role, n.NodeGroup, clusterNodeStateString(n.State))
		}
	}
	if len(st.Events) > 0 {
		fmt.Fprintln(w, "\nWHEN\tEVENT\tGROUP\tREASON")
		for _, e := range st.Events {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				e.At.AsTime().Format("2006-01-02 15:04:05"), scaleEventKindString(e.Kind), e.NodeGroup, e.Reason)
		}
	}
	return w.Flush()
}
