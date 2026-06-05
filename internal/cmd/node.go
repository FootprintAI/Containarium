package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/footprintai/containarium/pkg/core/nodevm"
	"github.com/spf13/cobra"
)

// `containarium node` carves the LOCAL hypervisor host into Containarium
// node-VMs (one GPU node + one CPU node, etc.). Host-local like `daemon`
// and `tunnel` — it drives the local `incus`, not a remote daemon, so it
// takes no --server. See docs/NODE-VM-PROVISIONING.md.

var nodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Carve this host into Containarium node-VMs (GPU/CPU nodes)",
	Long: `Provision Incus VMs on THIS host that each register with the sentinel
as a pool-tagged Containarium backend — e.g. a GPU node (VFIO passthrough)
plus a CPU node, from one physical box.

This runs locally against the host's Incus (no --server). See
docs/NODE-VM-PROVISIONING.md.

  containarium node prepare-gpu --gpu pci=0000:01:00.0   # one-time VFIO prep (reboot-class)
  containarium node provision --name cpu-node --kind cpu --pool cpu --cpu 16 --memory 64GiB --sentinel <addr>
  containarium node provision --name gpu-node --kind gpu --pool gpu --cpu 8 --memory 32GiB --gpu pci=0000:01:00.0 --sentinel <addr>
  containarium node list
  containarium node destroy --name cpu-node`,
}

var (
	nodeName        string
	nodeKind        string
	nodePool        string
	nodeCPU         int
	nodeMemory      string
	nodeDisk        string
	nodeGPU         string
	nodeSentinel    string
	nodeTunnelToken string
	nodeImage       string
	nodeBinary      string
)

var nodeProvisionCmd = &cobra.Command{
	Use:   "provision",
	Short: "Provision a node-VM (create VM + bootstrap daemon/tunnel)",
	RunE:  runNodeProvision,
}

var nodePrepareGPUCmd = &cobra.Command{
	Use:   "prepare-gpu",
	Short: "Print the one-time VFIO host prep for a GPU node (reboot-class)",
	Long: `Emit the exact steps to bind a GPU to vfio-pci so it can be passed to a
GPU node-VM. This is reboot-class and takes the GPU away from the host
(and any host-side GPU containers), so it PRINTS the plan for you to review
and run — it does not modify GRUB or reboot for you.`,
	RunE: runNodePrepareGPU,
}

var nodeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List node-VMs on this host",
	Args:  cobra.NoArgs,
	RunE:  runNodeList,
}

var nodeDestroyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Tear down a node-VM",
	RunE:  runNodeDestroy,
}

func init() {
	rootCmd.AddCommand(nodeCmd)
	nodeCmd.AddCommand(nodeProvisionCmd, nodePrepareGPUCmd, nodeListCmd, nodeDestroyCmd)

	pf := nodeProvisionCmd.Flags()
	pf.StringVar(&nodeName, "name", "", "node-VM name (required)")
	pf.StringVar(&nodeKind, "kind", "cpu", "node kind: 'cpu' or 'gpu'")
	pf.StringVar(&nodePool, "pool", "", "Containarium pool tag to register under (required)")
	pf.IntVar(&nodeCPU, "cpu", 0, "vCPUs for the VM (required)")
	pf.StringVar(&nodeMemory, "memory", "", "memory for the VM, e.g. 64GiB (required)")
	pf.StringVar(&nodeDisk, "disk", "", "root disk size, e.g. 200GiB (default: image default)")
	pf.StringVar(&nodeGPU, "gpu", "", "GPU PCI address for --kind gpu, e.g. pci=0000:01:00.0 or 0000:01:00.0")
	pf.StringVar(&nodeSentinel, "sentinel", os.Getenv("CONTAINARIUM_SENTINEL_ADDR"), "sentinel address host:port (env: CONTAINARIUM_SENTINEL_ADDR)")
	pf.StringVar(&nodeTunnelToken, "tunnel-token", os.Getenv("CONTAINARIUM_TUNNEL_TOKEN"), "tunnel auth token (prefer CONTAINARIUM_TUNNEL_TOKEN env)")
	pf.StringVar(&nodeImage, "image", nodevm.DefaultImage, "base image for the VM")
	pf.StringVar(&nodeBinary, "binary", "", "local containarium binary to push into the VM (default: this binary)")

	nodePrepareGPUCmd.Flags().StringVar(&nodeGPU, "gpu", "", "GPU PCI address, e.g. pci=0000:01:00.0 or 0000:01:00.0 (required)")
	nodeDestroyCmd.Flags().StringVar(&nodeName, "name", "", "node-VM name to destroy (required)")
}

// parseGPUPCI accepts "pci=0000:01:00.0" or "0000:01:00.0".
func parseGPUPCI(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "pci=")
}

func newNodeManager() (*nodevm.Manager, error) {
	runner, err := nodevm.NewCLIRunner()
	if err != nil {
		return nil, err
	}
	bin := nodeBinary
	if bin == "" {
		if self, err := os.Executable(); err == nil {
			bin = self
		}
	}
	return nodevm.NewManager(runner, bin), nil
}

func runNodeProvision(cmd *cobra.Command, args []string) error {
	spec := nodevm.Spec{
		Name:        nodeName,
		Kind:        nodevm.Kind(nodeKind),
		Pool:        nodePool,
		CPU:         nodeCPU,
		Memory:      nodeMemory,
		Disk:        nodeDisk,
		Image:       nodeImage,
		GPUPCI:      parseGPUPCI(nodeGPU),
		Sentinel:    nodeSentinel,
		TunnelToken: nodeTunnelToken,
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	if spec.TunnelToken == "" {
		return fmt.Errorf("a tunnel token is required (set CONTAINARIUM_TUNNEL_TOKEN or --tunnel-token) so the node can register")
	}
	m, err := newNodeManager()
	if err != nil {
		return err
	}
	fmt.Printf("Provisioning %s node %q (pool=%s, %d vCPU, %s)...\n", spec.Kind, spec.Name, spec.Pool, spec.CPU, spec.Memory)
	n, err := m.Provision(spec)
	if err != nil {
		return err
	}
	fmt.Printf("✓ node %q %s — registering with the sentinel as spot-id %q (pool %q)\n", n.Name, n.State, spec.SpotID(), spec.Pool)
	fmt.Printf("  verify:  containarium backends list   (look for %s)\n", spec.SpotID())
	return nil
}

func runNodePrepareGPU(cmd *cobra.Command, args []string) error {
	pci := parseGPUPCI(nodeGPU)
	if pci == "" {
		return fmt.Errorf("--gpu pci=<addr> is required")
	}
	fmt.Printf(`One-time VFIO prep to pass GPU %s into a node-VM.
⚠  REBOOT-CLASS and DESTRUCTIVE: this binds the GPU to vfio-pci, so the
   host (and any host-side GPU containers) LOSE the card until reversed.

Run as root, after reviewing:

  # 1. resolve the GPU's vendor:device IDs (and its audio function)
  lspci -nns %s

  # 2. enable IOMMU + reserve the GPU for vfio-pci
  sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="intel_iommu=on iommu=pt /' /etc/default/grub
  echo "options vfio-pci ids=<vendor:device>,<audio vendor:device>" > /etc/modprobe.d/vfio.conf
  printf 'vfio\nvfio_pci\nvfio_iommu_type1\n' > /etc/modules-load.d/vfio.conf
  update-grub && update-initramfs -u

  # 3. reboot, then verify the GPU is on vfio-pci:
  reboot
  lspci -nnk -s %s   # → "Kernel driver in use: vfio-pci"

Then: containarium node provision --kind gpu --gpu pci=%s ...
`, pci, pci, pci, pci)
	return nil
}

func runNodeList(cmd *cobra.Command, args []string) error {
	m, err := newNodeManager()
	if err != nil {
		return err
	}
	nodes, err := m.List()
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		fmt.Println("No node-VMs on this host.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATE")
	for _, n := range nodes {
		fmt.Fprintf(w, "%s\t%s\n", n.Name, n.State)
	}
	return w.Flush()
}

func runNodeDestroy(cmd *cobra.Command, args []string) error {
	if nodeName == "" {
		return fmt.Errorf("--name is required")
	}
	m, err := newNodeManager()
	if err != nil {
		return err
	}
	if err := m.Destroy(nodeName); err != nil {
		return err
	}
	fmt.Printf("✓ node-VM %q destroyed\n", nodeName)
	return nil
}
