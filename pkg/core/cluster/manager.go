package cluster

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// VMHost is the narrow host surface the manager drives — implemented
// by IncusHost in production and by a fake in tests, so orchestration
// sequences are unit-testable (the nodevm Runner-seam precedent).
type VMHost interface {
	// VMCapable returns nil when the host can run VMs, or a typed,
	// user-facing error when it cannot (the design's hard create-time
	// requirement).
	VMCapable() error
	// ContainerNodeCapable is the container-class counterpart
	// (#1429): nil when the host can run k3s node containers, or a
	// refusal naming every missing (or unverifiable) precondition.
	ContainerNodeCapable() error
	// NodeCapacityCapable is the per-node half of the container probe
	// (#1439): nil when a container node of this size can advertise a
	// truthful capacity on this host, a refusal when it cannot.
	NodeCapacityCapable(spec NodeSpec) error
	// CreateNode creates one cluster node backed by the instance type
	// the isolation class selects: an Incus VM, or a system container
	// carrying the container node profile (#1429).
	CreateNode(spec NodeSpec, isolation Isolation) error
	Start(name string) error
	// Stop halts a node. Deleting a running instance is refused by
	// Incus, so this is a required step of removal, not a nicety.
	Stop(name string) error
	Delete(name string) error
	// WaitReady blocks until the guest agent is up and networked,
	// returning the VM's primary IP.
	WaitReady(name string, timeout time.Duration) (string, error)
	Push(name, path string, content []byte, mode string) error
	Read(name, path string) ([]byte, error)
	Exec(name string, cmd []string) (string, error)
	// ClusterVMs lists this cluster's VMs by label, bucketed as the
	// reconciler's Observed shape.
	ClusterVMs(tenant, clusterName string) (Observed, error)
}

// Manager provisions cluster VMs. It is stateless: every method takes
// what it needs, and persistence stays with the caller.
type Manager struct {
	host VMHost
	// k3sBinary loads the host-cached, checksum-verified binary
	// (EnsureK3s). A loader keeps ~70MB out of memory until a
	// provision actually happens.
	k3sBinary func() ([]byte, error)
	// waitReadyTimeout is how long a fresh VM gets to boot + network.
	waitReadyTimeout time.Duration
}

// NewManager builds a Manager on a host. artifactBase is the host
// cache root (DefaultArtifactBase in production).
func NewManager(host VMHost, artifactBase string) *Manager {
	return &Manager{
		host: host,
		k3sBinary: func() ([]byte, error) {
			path, err := EnsureK3s(context.Background(), artifactBase)
			if err != nil {
				return nil, err
			}
			return os.ReadFile(path)
		},
		waitReadyTimeout: 3 * time.Minute,
	}
}

// NewManagerWithLoader builds a Manager with an explicit binary
// loader — the seam tests (and callers with pre-staged artifacts) use
// instead of the EnsureK3s download path.
func NewManagerWithLoader(host VMHost, loader func() ([]byte, error)) *Manager {
	return &Manager{host: host, k3sBinary: loader, waitReadyTimeout: 3 * time.Minute}
}

// VMCapable surfaces the host's VM capability probe.
func (m *Manager) VMCapable() error { return m.host.VMCapable() }

// ContainerNodeCapable surfaces the host's container-node probe (#1429).
func (m *Manager) ContainerNodeCapable() error { return m.host.ContainerNodeCapable() }

// Observe returns the host's view of a cluster's VMs.
func (m *Manager) Observe(tenant, clusterName string) (Observed, error) {
	return m.host.ClusterVMs(tenant, clusterName)
}

// StartVM restarts a stopped cluster VM.
func (m *Manager) StartVM(name string) error { return m.host.Start(name) }

// DeleteVM removes a cluster node, stopping it first.
//
// Incus refuses to delete a running instance ("Instance is running"),
// so the stop is part of the removal rather than an optimisation. The
// tenant container path has always done this; the cluster path did
// not, which meant the autoscaler could never complete a scale-down
// and `cluster delete` left every instance of the cluster running on
// the host (#1475).
//
// A stop error is deliberately ignored: the common case is a node that
// is already stopped, which Incus reports as an error, and any stop
// failure that actually matters resurfaces as a delete failure. The
// delete's error is the one the caller sees — the autoscaler retries on
// it, so swallowing it would make a failed scale-down look successful.
func (m *Manager) DeleteVM(name string) error {
	_ = m.host.Stop(name)
	return m.host.Delete(name)
}

const bootstrapScriptPath = "/root/containarium-bootstrap.sh"

// pushFile writes a file into a node, creating its parent directory
// first. Incus answers "Not Found" when the parent is missing, and
// none of the directories the cluster flow writes into
// (/etc/containarium, its ca/ subdir, k3s's manifests dir) exist in a
// fresh node image — so every push failed until the parent was made
// (#1442). mkdir -p is idempotent, so this is safe on the paths whose
// parent already exists.
func (m *Manager) pushFile(name, path string, content []byte, mode string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "/" && dir != "." {
		if _, err := m.host.Exec(name, []string{"mkdir", "-p", dir}); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	return m.host.Push(name, path, content, mode)
}

// observedNodeCapacity asks a BOOTED node what it observes as its own
// capacity, by reading the two files cadvisor derives node capacity
// from inside the node itself.
//
// This vantage point is the whole correction of #1466. The daemon
// host's /proc cannot answer the question: on a plain Incus host
// lxcfs masks these files and the node sees its real limits, while on
// a nested host masking does not reach the inner instance and the node
// sees the outer host. The two are indistinguishable from outside, and
// guessing wrong in either direction has already shipped a bug —
// #1456 (reservation applied where none was needed; kubelet refused to
// start) and #1466 (no reservation where one was needed; autoscaling
// silently disabled).
func (m *Manager) observedNodeCapacity(name string) (int, int64, error) {
	cpuinfo, err := m.host.Exec(name, []string{"cat", ProcCPUInfoPath})
	if err != nil {
		return 0, 0, fmt.Errorf("read %s on %s: %w", ProcCPUInfoPath, name, err)
	}
	meminfo, err := m.host.Exec(name, []string{"cat", ProcMemInfoPath})
	if err != nil {
		return 0, 0, fmt.Errorf("read %s on %s: %w", ProcMemInfoPath, name, err)
	}
	return ParseProcCapacity(cpuinfo, meminfo)
}

// containerKubeletArgs assembles the kubelet flags a container-class
// node needs, given what that node — already booted — reports about
// itself.
//
// Two flags, for two different failures:
//
//   - The user-namespace gate (#1452), always. kubelet writes kernel
//     sysctls an unprivileged container may not touch, and without the
//     gate ContainerManager never starts.
//   - A reservation, ONLY when the node actually misreports (#1466).
//     Allocatable = capacity - reserved, and both the scheduler and
//     cluster-autoscaler's fit simulation read allocatable; a node
//     advertising the outer host's 8 cpu instead of its own 2 gets
//     packed with pods it cannot run and never triggers the scale-up
//     that should have happened.
//
// The trigger is what took three attempts to get right. #1452 computed
// the reservation from (daemon host capacity - requested size) and
// applied it unconditionally, on the premise that a container node
// always reports the host's capacity. That premise holds only on a
// NESTED host. On a plain host the node sees its real limit, the
// reservation exceeded the node's entire capacity, and kubelet refused
// to start ("capacity >= reservation") — so the correction meant to
// make allocatable truthful stopped the node running at all (#1456,
// removed in #1457). Asking the node is the only thing that
// distinguishes the two, so that is what this does.
//
// A zero reservation renders no flags: where the node already observes
// its own size the stock kubelet is correct.
func (m *Manager) containerKubeletArgs(iso Isolation, spec NodeSpec) ([]string, error) {
	if iso != IsolationContainer {
		return nil, nil
	}
	cpu, mem, err := m.observedNodeCapacity(spec.Name)
	if err != nil {
		// Fail closed. An unmeasurable node is not a node that
		// observes itself correctly — proceeding without a
		// reservation is precisely the silent failure #1466 exists to
		// end, and it would leave no trace anywhere.
		return nil, fmt.Errorf(
			"cannot establish %s's observed capacity, so its allocatable cannot be made truthful: %w",
			spec.Name, err)
	}
	reserved, err := NodeReservation(cpu, mem, spec)
	if err != nil {
		return nil, fmt.Errorf("node %s: %w", spec.Name, err)
	}
	return ContainerKubeletArgs(KubeletReservedArgs(reserved)), nil
}

// ProvisionCP creates and bootstraps the control-plane VM: create →
// start → wait → push pinned binary + rendered script → exec. Returns
// the VM's IP (workers join over it). cpSize is the smallest preset —
// the control plane is platform overhead, not tenant capacity.
func (m *Manager) ProvisionCP(tenant, clusterName string, iso Isolation, cpSize DesiredGroup, tlsSANs []string) (string, error) {
	name := CPName(tenant, clusterName)
	spec := NodeSpec{
		Name: name, CPU: cpSize.CPU, Memory: cpSize.Memory, Disk: cpSize.Disk,
		Labels: VMLabels(tenant, clusterName, RoleControlPlane, ""),
	}
	if err := m.host.CreateNode(spec, iso); err != nil {
		return "", fmt.Errorf("create control-plane node: %w", err)
	}
	ip, err := m.host.WaitReady(name, m.waitReadyTimeout)
	if err != nil {
		return "", fmt.Errorf("control-plane VM %s not ready: %w", name, err)
	}
	bin, err := m.k3sBinary()
	if err != nil {
		return "", err
	}
	if err := m.pushFile(name, K3sBinaryPath, bin, "0755"); err != nil {
		return "", fmt.Errorf("push k3s binary: %w", err)
	}
	kubeletArgs, err := m.containerKubeletArgs(iso, spec)
	if err != nil {
		return "", fmt.Errorf("control-plane kubelet args: %w", err)
	}
	script := RenderServerScript(ServerBootstrap{
		TLSSANs:     append([]string{ip}, tlsSANs...),
		Isolation:   iso,
		KubeletArgs: kubeletArgs,
	})
	if err := m.pushFile(name, bootstrapScriptPath, []byte(script), "0755"); err != nil {
		return "", fmt.Errorf("push bootstrap script: %w", err)
	}
	if _, err := m.host.Exec(name, []string{"sh", bootstrapScriptPath}); err != nil {
		return "", fmt.Errorf("control-plane bootstrap: %w", err)
	}
	return ip, nil
}

// ProvisionWorker creates and joins one worker VM to a running control
// plane. The join token is read from the CP and pushed 0600 — it never
// leaves the host or lands in a store.
func (m *Manager) ProvisionWorker(tenant, clusterName string, iso Isolation, g DesiredGroup, vmName, cpIP string) error {
	cp := CPName(tenant, clusterName)
	token, err := m.host.Read(cp, NodeTokenPath)
	if err != nil {
		return fmt.Errorf("read join token from %s: %w", cp, err)
	}
	spec := NodeSpec{
		Name: vmName, CPU: g.CPU, Memory: g.Memory, Disk: g.Disk,
		Labels: VMLabels(tenant, clusterName, RoleWorker, g.Name),
	}
	// Container nodes read the host's /proc as their own capacity, so
	// a host too small for this size would produce a node advertising
	// resources it does not have (#1439). Refuse before creating it:
	// the scheduler and the autoscaler's fit simulation both trust
	// node allocatable, so the lie is not locally contained. VM nodes
	// get their own kernel and report honestly, so they skip this.
	if iso == IsolationContainer {
		if err := m.host.NodeCapacityCapable(spec); err != nil {
			return fmt.Errorf("worker node capacity: %w", err)
		}
	}
	if err := m.host.CreateNode(spec, iso); err != nil {
		return fmt.Errorf("create worker node: %w", err)
	}
	if _, err := m.host.WaitReady(vmName, m.waitReadyTimeout); err != nil {
		return fmt.Errorf("worker VM %s not ready: %w", vmName, err)
	}
	bin, err := m.k3sBinary()
	if err != nil {
		return err
	}
	if err := m.pushFile(vmName, K3sBinaryPath, bin, "0755"); err != nil {
		return fmt.Errorf("push k3s binary: %w", err)
	}
	if err := m.pushFile(vmName, AgentTokenPath, token, "0600"); err != nil {
		return fmt.Errorf("push join token: %w", err)
	}
	// A container-class worker cannot derive its own containerd
	// template: k3s agent writes config.toml only after retrieving
	// configuration from the server, so waiting for it in the bootstrap
	// blocks on something downstream of the startup being blocked
	// (#1448). Derive from the control plane's generated config — same
	// pinned k3s version, same base shape — and push it before boot.
	if iso == IsolationContainer {
		generated, err := m.host.Read(cp, ContainerdGeneratedConfigPath)
		if err != nil {
			return fmt.Errorf("read containerd config from %s: %w", cp, err)
		}
		tmpl, err := DeriveContainerdTemplate(generated)
		if err != nil {
			return fmt.Errorf("derive containerd template: %w", err)
		}
		if err := m.pushFile(vmName, ContainerdConfigTemplatePath, tmpl, "0644"); err != nil {
			return fmt.Errorf("push containerd template: %w", err)
		}
	}
	kubeletArgs, err := m.containerKubeletArgs(iso, spec)
	if err != nil {
		return fmt.Errorf("worker kubelet args: %w", err)
	}
	script := RenderAgentScript(AgentBootstrap{
		ServerURL:   "https://" + cpIP + ":6443",
		Isolation:   iso,
		KubeletArgs: kubeletArgs,
	})
	if err := m.pushFile(vmName, bootstrapScriptPath, []byte(script), "0755"); err != nil {
		return fmt.Errorf("push bootstrap script: %w", err)
	}
	if _, err := m.host.Exec(vmName, []string{"sh", bootstrapScriptPath}); err != nil {
		return fmt.Errorf("worker bootstrap: %w", err)
	}
	return nil
}

// Kubeconfig reads the CP's admin kubeconfig on demand and rewrites
// its server URL to the published endpoint. Never persisted.
func (m *Manager) Kubeconfig(tenant, clusterName, endpoint string) (string, error) {
	raw, err := m.host.Read(CPName(tenant, clusterName), KubeconfigPath)
	if err != nil {
		return "", fmt.Errorf("read kubeconfig: %w", err)
	}
	kc := string(raw)
	if endpoint != "" {
		kc = RewriteKubeconfigServer(kc, endpoint)
	}
	return kc, nil
}

// CPIP returns the control-plane VM's current IP.
func (m *Manager) CPIP(tenant, clusterName string) (string, error) {
	return m.host.WaitReady(CPName(tenant, clusterName), 30*time.Second)
}

// ReadyNodes counts Ready nodes as the cluster's own API reports them,
// via `k3s kubectl` on the CP — observed state from the cluster, not
// from our rows.
func (m *Manager) ReadyNodes(tenant, clusterName string) (int, error) {
	out, err := m.host.Exec(CPName(tenant, clusterName),
		[]string{K3sBinaryPath, "kubectl", "get", "nodes", "--no-headers"})
	if err != nil {
		return 0, fmt.Errorf("kubectl get nodes: %w", err)
	}
	ready := 0
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "Ready" {
			ready++
		}
	}
	return ready, nil
}

// CACredentials is the per-cluster mTLS client credential the CA unit
// presents to the daemon's provider listener.
type CACredentials struct {
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	CACertPEM     []byte
}

// DeployCA installs the cluster-autoscaler onto a provisioned control
// plane: credential files (key 0600), the externalgrpc cloud-config,
// and the digest-pinned unit. Idempotent — re-running replaces the
// files and re-enables the unit.
func (m *Manager) DeployCA(tenant, clusterName string, d CADeploy, creds CACredentials) error {
	cp := CPName(tenant, clusterName)
	files := []struct {
		path    string
		content []byte
		mode    string
	}{
		{CAClientCertPath, creds.ClientCertPEM, "0644"},
		{CAClientKeyPath, creds.ClientKeyPEM, "0600"},
		{CACACertPath, creds.CACertPEM, "0644"},
		{CACloudConfigPath, []byte(RenderCACloudConfig(d)), "0644"},
	}
	for _, f := range files {
		if err := m.pushFile(cp, f.path, f.content, f.mode); err != nil {
			return fmt.Errorf("push %s: %w", f.path, err)
		}
	}
	script := RenderCAUnitScript(d)
	if err := m.pushFile(cp, "/root/containarium-ca-bootstrap.sh", []byte(script), "0755"); err != nil {
		return fmt.Errorf("push CA bootstrap: %w", err)
	}
	if _, err := m.host.Exec(cp, []string{"sh", "/root/containarium-ca-bootstrap.sh"}); err != nil {
		return fmt.Errorf("CA bootstrap: %w", err)
	}
	return nil
}
