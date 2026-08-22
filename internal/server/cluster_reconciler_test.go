package server

// Reconciler coverage (#1414): the REAL Manager and MemStore drive a
// stateful fake host, entered through the real ClusterServer handlers —
// so these tests pin the whole daemon-side loop except Incus itself
// (which the gated KVM e2e lane #1418 owns).

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	clustercore "github.com/footprintai/containarium/pkg/core/cluster"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// stateHost is a stateful VMHost fake: created VMs exist and run,
// pushed files persist, and the in-cluster kubectl reports every
// existing VM as a Ready node.
type stateHost struct {
	mu              sync.Mutex
	vms             map[string]*stateVM
	files           map[string][]byte
	capErr          error
	containerCapErr error
	capacityErr     error
	// isolations records the class each node was created with (#1429).
	isolations map[string]clustercore.Isolation
	// onDelete fires inside Delete, before the instance is removed.
	// It exists so a test can drive a reconciler pass into the middle
	// of a DeleteNodes batch — the interleaving that recreated a
	// drained node in production (#1498) and cannot be reproduced by
	// calling the two in sequence.
	onDelete func(name string)
	// execCalls records every Exec argv, so a test can assert on what
	// the control plane was actually told to do rather than on the
	// code that was supposed to tell it.
	execCalls []string
}

type stateVM struct {
	labels  map[string]string
	running bool
	// cpu/mem are the size the node was created with. The fake serves
	// them back through /proc so a container-class provision can read
	// its own capacity the way the real probe does (#1466) — an
	// HONEST node, seeing exactly its own limits.
	cpu string
	mem string
}

func newStateHost() *stateHost {
	return &stateHost{vms: map[string]*stateVM{}, files: map[string][]byte{}, isolations: map[string]clustercore.Isolation{}}
}

func (h *stateHost) VMCapable() error            { return h.capErr }
func (h *stateHost) ContainerNodeCapable() error { return h.containerCapErr }

func (h *stateHost) NodeCapacityCapable(clustercore.NodeSpec) error { return h.capacityErr }

func (h *stateHost) CreateNode(spec clustercore.NodeSpec, isolation clustercore.Isolation) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.vms[spec.Name]; ok {
		return fmt.Errorf("vm %s already exists", spec.Name)
	}
	h.vms[spec.Name] = &stateVM{labels: spec.Labels, running: true, cpu: spec.CPU, mem: spec.Memory}
	h.isolations[spec.Name] = isolation
	// A booted CP "writes" its own kubeconfig and join token.
	if spec.Labels[clustercore.LabelClusterRole] == clustercore.RoleControlPlane {
		h.files[spec.Name+":"+clustercore.KubeconfigPath] = []byte("clusters:\n- cluster:\n    server: https://127.0.0.1:6443\n")
		h.files[spec.Name+":"+clustercore.NodeTokenPath] = []byte("K10::join-token")
		// k3s writes its generated containerd config on start, and a
		// container-class worker derives its template from the CP's
		// copy (#1448) — without it no container worker can be
		// provisioned here at all.
		h.files[spec.Name+":"+clustercore.ContainerdGeneratedConfigPath] = []byte(
			"version = 3\n[plugins.'io.containerd.cri.v1.runtime']\n" +
				"  enable_unprivileged_ports = true\n  enable_unprivileged_icmp = true\n")
	}
	return nil
}

func (h *stateHost) Start(name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	vm, ok := h.vms[name]
	if !ok {
		return fmt.Errorf("no vm %s", name)
	}
	vm.running = true
	return nil
}

// Stop mirrors Incus: stopping an instance that is not there is an
// error, and stopping one that is already stopped is too. DeleteVM
// ignores both, which is what this fake is here to let us prove.
func (h *stateHost) Stop(name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	vm, ok := h.vms[name]
	if !ok {
		return fmt.Errorf("no vm %s", name)
	}
	vm.running = false
	return nil
}

func (h *stateHost) Delete(name string) error {
	h.mu.Lock()
	if _, ok := h.vms[name]; !ok {
		h.mu.Unlock()
		return fmt.Errorf("no vm %s", name)
	}
	delete(h.vms, name)
	hook := h.onDelete
	h.mu.Unlock()

	// Fired with the instance already gone and the caller not yet
	// returned — the production window, where a reconciler tick sees
	// a group short of a target that has not been lowered yet
	// (#1498). Outside the lock, because the hook re-enters this fake
	// through the reconciler exactly as a real tick would.
	if hook != nil {
		hook(name)
	}
	return nil
}

func (h *stateHost) WaitReady(name string, _ time.Duration) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.vms[name]; !ok {
		return "", fmt.Errorf("no vm %s", name)
	}
	return "10.166.11.5", nil
}

func (h *stateHost) Push(name, path string, content []byte, mode string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files[name+":"+path] = content
	return nil
}

func (h *stateHost) Read(name, path string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.files[name+":"+path]; ok {
		return c, nil
	}
	return nil, errors.New("no such file")
}

func (h *stateHost) Exec(name string, cmd []string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// The container-class capacity probe reads the node's own /proc
	// (#1466). Without this the probe fails, the provision aborts, and
	// a test that only checks "the instance exists" still passes —
	// because CreateNode ran before the abort.
	if len(cmd) == 2 && cmd[0] == "cat" {
		vm, ok := h.vms[name]
		if !ok {
			return "", fmt.Errorf("no vm %s", name)
		}
		switch cmd[1] {
		case clustercore.ProcCPUInfoPath:
			n, err := strconv.Atoi(vm.cpu)
			if err != nil {
				return "", err
			}
			var b strings.Builder
			for i := 0; i < n; i++ {
				fmt.Fprintf(&b, "processor\t: %d\n", i)
			}
			return b.String(), nil
		case clustercore.ProcMemInfoPath:
			bytes, err := clustercore.ParseSizeBytes(vm.mem)
			if err != nil {
				return "", err
			}
			// Report just under the configured size, as a real kernel
			// does — MemTotal excludes firmware-reserved memory.
			return fmt.Sprintf("MemTotal:%15d kB\n", (bytes-6_144)/1024), nil
		}
	}
	h.execCalls = append(h.execCalls, name+": "+strings.Join(cmd, " "))
	// Only `kubectl get nodes` lists nodes. Answering the node list to
	// every kubectl subcommand would make a `delete secret` look like
	// a success no matter what it was handed.
	if len(cmd) >= 3 && cmd[1] == "kubectl" && cmd[2] == "get" {
		var b strings.Builder
		for vm := range h.vms {
			fmt.Fprintf(&b, "%s   Ready   <none>   1m   v-test\n", vm)
		}
		return b.String(), nil
	}
	return "", nil
}

// execs returns a copy of the recorded Exec argv list.
func (h *stateHost) execs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.execCalls...)
}

func (h *stateHost) ClusterVMs(tenant, clusterName string) (clustercore.Observed, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	obs := clustercore.Observed{Workers: map[string][]clustercore.ObservedVM{}}
	for name, vm := range h.vms {
		if vm.labels[clustercore.LabelCluster] != clusterName || vm.labels[clustercore.LabelClusterOwner] != tenant {
			continue
		}
		o := clustercore.ObservedVM{Name: name, Running: vm.running}
		switch vm.labels[clustercore.LabelClusterRole] {
		case clustercore.RoleControlPlane:
			cp := o
			obs.CP = &cp
		case clustercore.RoleWorker:
			g := vm.labels[clustercore.LabelNodeGroup]
			obs.Workers[g] = append(obs.Workers[g], o)
		}
	}
	return obs, nil
}

func testReconcilerRig(t *testing.T) (*ClusterServer, *ClusterReconciler, *stateHost) {
	t.Helper()
	host := newStateHost()
	mgr := clustercore.NewManagerWithLoader(host, func() ([]byte, error) { return []byte("k3s-bin"), nil })
	srv := clusterTestServer()
	rec := NewClusterReconciler(srv.Store(), mgr)
	srv.SetReconciler(rec)
	return srv, rec, host
}

func TestReconciler_ProvisionsToReady(t *testing.T) {
	srv, rec, host := testReconcilerRig(t)
	ctx := context.Background()
	mustCreate(t, srv, tenantCtx("alice"), "demo") // default presets: small min=1

	// Pass 1: control plane first, no workers yet.
	rec.ReconcileOnce(ctx)
	if _, ok := host.vms["alice-k8s-demo-cp"]; !ok {
		t.Fatalf("pass 1 did not create the control plane; vms=%v", vmNames(host))
	}
	if len(host.vms) != 1 {
		t.Fatalf("pass 1 created workers before the CP was observed running: %v", vmNames(host))
	}

	// Pass 2: worker to min, endpoint recorded, cluster READY (the
	// fake cluster API reports both nodes Ready).
	rec.ReconcileOnce(ctx)
	if _, ok := host.vms["alice-k8s-demo-small-1"]; !ok {
		t.Fatalf("pass 2 did not create the small worker: %v", vmNames(host))
	}
	// Worker got the binary, the 0600 token, and a join script.
	if string(host.files["alice-k8s-demo-small-1:"+clustercore.AgentTokenPath]) != "K10::join-token" {
		t.Fatal("worker did not receive the CP's join token")
	}

	rec.ReconcileOnce(ctx) // settle
	got, err := srv.GetCluster(tenantCtx("alice"), &pb.GetClusterRequest{Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Cluster.State != pb.ClusterState_CLUSTER_STATE_READY {
		t.Fatalf("state = %v, want READY (reason %q)", got.Cluster.State, got.Cluster.StateReason)
	}
	if got.Cluster.ApiEndpoint != "10.166.11.5:6443" {
		t.Fatalf("endpoint = %q (publish seam nil → CP IP)", got.Cluster.ApiEndpoint)
	}

	// Kubeconfig now flows through the reconciler's reader, rewritten
	// to the recorded endpoint.
	kc, err := srv.GetClusterKubeconfig(tenantCtx("alice"), &pb.GetClusterKubeconfigRequest{Name: "demo"})
	if err != nil {
		t.Fatalf("kubeconfig: %v", err)
	}
	if !strings.Contains(kc.Kubeconfig, "server: https://10.166.11.5:6443") {
		t.Fatalf("kubeconfig not rewritten:\n%s", kc.Kubeconfig)
	}

	// Status shows the worker row and per-group counts.
	st, err := srv.GetClusterStatus(tenantCtx("alice"), &pb.GetClusterStatusRequest{Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Nodes) != 2 {
		t.Fatalf("status nodes = %d, want cp+worker", len(st.Nodes))
	}
}

func TestReconciler_ReplacesLostWorker(t *testing.T) {
	srv, rec, host := testReconcilerRig(t)
	ctx := context.Background()
	mustCreate(t, srv, tenantCtx("alice"), "demo")
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)

	// Kill the worker out-of-band.
	delete(host.vms, "alice-k8s-demo-small-1")

	rec.ReconcileOnce(ctx)
	if _, ok := host.vms["alice-k8s-demo-small-1"]; !ok {
		t.Fatalf("lost worker not replaced: %v", vmNames(host))
	}
	// The replacement is on the scale-event record.
	st, err := srv.GetClusterStatus(tenantCtx("alice"), &pb.GetClusterStatusRequest{Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Events) == 0 {
		t.Fatal("no scale events recorded for the replacement")
	}
}

func TestReconciler_AsyncDeleteDrainsEverything(t *testing.T) {
	srv, rec, host := testReconcilerRig(t)
	ctx := context.Background()
	mustCreate(t, srv, tenantCtx("alice"), "demo")
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)

	resp, err := srv.DeleteCluster(tenantCtx("alice"), &pb.DeleteClusterRequest{Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Message, "in progress") {
		t.Fatalf("async delete message = %q", resp.Message)
	}
	// Record still present (DELETING) until the reconciler drains it.
	if _, err := srv.GetCluster(tenantCtx("alice"), &pb.GetClusterRequest{Name: "demo"}); err != nil {
		t.Fatalf("record vanished before the reconciler ran: %v", err)
	}

	rec.ReconcileOnce(ctx) // deletes VMs
	rec.ReconcileOnce(ctx) // observes empty, drops rows
	if len(host.vms) != 0 {
		t.Fatalf("VMs survived deletion: %v", vmNames(host))
	}
	_, err = srv.GetCluster(tenantCtx("alice"), &pb.GetClusterRequest{Name: "demo"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("record after drain = %v, want NotFound", err)
	}
	// Name immediately reusable.
	mustCreate(t, srv, tenantCtx("alice"), "demo")
}

func TestReconciler_AdmissionRefusalIsLoud(t *testing.T) {
	srv, rec, host := testReconcilerRig(t)
	ctx := context.Background()
	rec.SetAdmission(func(owner, cpu string) error { return errors.New("host at capacity") })
	mustCreate(t, srv, tenantCtx("alice"), "demo")

	rec.ReconcileOnce(ctx)
	if len(host.vms) != 0 {
		t.Fatalf("VM created despite admission refusal: %v", vmNames(host))
	}
	st, err := srv.GetClusterStatus(tenantCtx("alice"), &pb.GetClusterStatusRequest{Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Events) == 0 || st.Events[0].Kind != pb.ScaleEventKind_SCALE_EVENT_KIND_REFUSED {
		t.Fatalf("refusal not recorded as a REFUSED event: %+v", st.Events)
	}
}

func TestReconciler_VMCapabilityGatesCreate(t *testing.T) {
	srv, _, host := testReconcilerRig(t)
	host.capErr = clustercore.ErrVMsUnsupported

	_, err := srv.CreateCluster(tenantCtx("alice"), &pb.CreateClusterRequest{Name: "demo"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("create on a VM-incapable host = %v, want FailedPrecondition", err)
	}
	if !strings.Contains(err.Error(), "virtual machines") {
		t.Fatalf("error does not explain the capability gap: %v", err)
	}
}

func vmNames(h *stateHost) []string {
	var out []string
	for n := range h.vms {
		out = append(out, n)
	}
	return out
}

// The create-time capability probe dispatches on the cluster's
// isolation class (#1429): a VM cluster is gated by VMCapable only, a
// container cluster by ContainerNodeCapable only.
func TestReconciler_CapabilityProbeMatchesIsolation(t *testing.T) {
	vmErr := clustercore.ErrVMsUnsupported
	containerErr := fmt.Errorf("%w: br_netfilter: kernel module not present", clustercore.ErrContainerNodesUnsupported)

	cases := []struct {
		name            string
		isolation       pb.NodeIsolation
		vmCapErr        error
		containerCapErr error
		wantCode        codes.Code // OK = create allowed
		wantIn          string
	}{
		{"vm cluster gated by the VM probe", pb.NodeIsolation_NODE_ISOLATION_VM, vmErr, nil, codes.FailedPrecondition, "virtual machines"},
		{"vm cluster ignores the container probe", pb.NodeIsolation_NODE_ISOLATION_VM, nil, containerErr, codes.OK, ""},
		{"container cluster gated by the container probe, refusal names the precondition", pb.NodeIsolation_NODE_ISOLATION_CONTAINER, nil, containerErr, codes.FailedPrecondition, "br_netfilter"},
		{"container cluster does not require VM capability", pb.NodeIsolation_NODE_ISOLATION_CONTAINER, vmErr, nil, codes.OK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, host := testReconcilerRig(t)
			srv.SetIsolationGateFromEnv("true")
			host.capErr, host.containerCapErr = tc.vmCapErr, tc.containerCapErr

			_, err := srv.CreateCluster(tenantCtx("alice"), &pb.CreateClusterRequest{
				Name: "demo", NodeIsolation: tc.isolation,
			})
			if status.Code(err) != tc.wantCode {
				t.Fatalf("CreateCluster = %v, want code %v", err, tc.wantCode)
			}
			if tc.wantIn != "" && !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("refusal %q does not name %q", err, tc.wantIn)
			}
		})
	}
}

// A container cluster's nodes are provisioned as container nodes all
// the way down the seam; a default cluster's stay VM (#1429).
func TestReconciler_ProvisionIsolationMatchesCluster(t *testing.T) {
	cases := []struct {
		name      string
		isolation pb.NodeIsolation
		want      clustercore.Isolation
	}{
		{"default cluster provisions VM nodes", pb.NodeIsolation_NODE_ISOLATION_UNSPECIFIED, clustercore.IsolationVM},
		{"container cluster provisions container nodes", pb.NodeIsolation_NODE_ISOLATION_CONTAINER, clustercore.IsolationContainer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, rec, host := testReconcilerRig(t)
			srv.SetIsolationGateFromEnv("true")
			ctx := context.Background()
			if _, err := srv.CreateCluster(tenantCtx("alice"), &pb.CreateClusterRequest{
				Name: "demo", NodeIsolation: tc.isolation,
			}); err != nil {
				t.Fatalf("CreateCluster: %v", err)
			}

			rec.ReconcileOnce(ctx) // control plane
			rec.ReconcileOnce(ctx) // workers to min
			if len(host.vms) < 2 {
				t.Fatalf("expected CP + worker, got %v", vmNames(host))
			}
			for name := range host.vms {
				if got := host.isolations[name]; got != tc.want {
					t.Fatalf("node %s created with isolation %q, want %q", name, got, tc.want)
				}
				// Existence is not provisioning. CreateNode runs before
				// anything that can fail later in the sequence, so a
				// provision that aborted after it still leaves an
				// instance here — which is how a broken container path
				// passed this test unnoticed (#1466 review). Assert the
				// node was actually bootstrapped.
				if _, ok := host.files[name+":/root/containarium-bootstrap.sh"]; !ok {
					t.Fatalf("node %s exists but was never bootstrapped; provisioning aborted after CreateNode", name)
				}
			}
		})
	}
}

// The published endpoint must be a subject-alt-name on the API server
// certificate, or the kubeconfig the product hands a tenant cannot
// verify — precisely what run 14 of the container lane hit:
//
//	x509: certificate is valid for 10.100.0.102, 10.43.0.1, 127.0.0.1,
//	  ::1, fd42:..., not <advertise-host>
//
// The design always intended this ("TLSSANs are ... the external
// endpoint and the VM IP, so the rewritten kubeconfig verifies"); the
// reconciler simply passed nil (#1464).
func TestReconcilerGivesControlPlaneTheAdvertiseSAN(t *testing.T) {
	srv, rec, host := testReconcilerRig(t)
	rec.advertiseHost = "198.51.100.20"
	mustCreate(t, srv, tenantCtx("alice"), "demo")

	rec.ReconcileOnce(context.Background())

	script := string(host.files["alice-k8s-demo-cp:/root/containarium-bootstrap.sh"])
	if script == "" {
		t.Fatal("control plane was never bootstrapped")
	}
	if !strings.Contains(script, "--tls-san 198.51.100.20") {
		t.Errorf("control-plane cert will not cover the published endpoint:\n%s", script)
	}
}
