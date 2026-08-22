package cluster

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeHost records every VMHost call so tests assert the exact
// orchestration sequence — the part of the manager that matters.
type fakeHost struct {
	calls             []string
	files             map[string][]byte // "<vm>:<path>" → content
	execOut           map[string]string // "<vm>:<argv0...>" → stdout
	readErr           error
	capError          error
	containerCapError error
	capacityError     error
	// isolations records the isolation class CreateNode was called
	// with, per node name (#1429 acceptance: the fake records the
	// isolation per call).
	isolations map[string]Isolation
	stopErr    error
	deleteErr  error
}

func newFakeHost() *fakeHost {
	return &fakeHost{files: map[string][]byte{}, execOut: map[string]string{}, isolations: map[string]Isolation{}}
}

func (f *fakeHost) record(format string, a ...any) {
	f.calls = append(f.calls, fmt.Sprintf(format, a...))
}

func (f *fakeHost) VMCapable() error            { return f.capError }
func (f *fakeHost) ContainerNodeCapable() error { return f.containerCapError }

func (f *fakeHost) NodeCapacityCapable(NodeSpec) error { return f.capacityError }
func (f *fakeHost) CreateNode(spec NodeSpec, isolation Isolation) error {
	f.record("create %s cpu=%s mem=%s disk=%s role=%s", spec.Name, spec.CPU, spec.Memory, spec.Disk, spec.Labels[LabelClusterRole])
	f.isolations[spec.Name] = isolation
	return nil
}
func (f *fakeHost) Start(name string) error { f.record("start %s", name); return nil }
func (f *fakeHost) Stop(name string) error  { f.record("stop %s", name); return f.stopErr }
func (f *fakeHost) Delete(name string) error {
	f.record("delete %s", name)
	return f.deleteErr
}
func (f *fakeHost) WaitReady(name string, _ time.Duration) (string, error) {
	f.record("wait %s", name)
	return "10.166.11.5", nil
}
func (f *fakeHost) Push(name, path string, content []byte, mode string) error {
	f.record("push %s:%s mode=%s", name, path, mode)
	f.files[name+":"+path] = content
	return nil
}
func (f *fakeHost) Read(name, path string) ([]byte, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	f.record("read %s:%s", name, path)
	if c, ok := f.files[name+":"+path]; ok {
		return c, nil
	}
	return []byte("stored-content"), nil
}
func (f *fakeHost) Exec(name string, cmd []string) (string, error) {
	f.record("exec %s:%s", name, strings.Join(cmd, " "))
	// Keyed on the whole argv first so a test can stub two commands
	// that share an argv0 (cat /proc/cpuinfo vs cat /proc/meminfo);
	// argv0 alone remains for the stubs that predate that need.
	if out, ok := f.execOut[name+":"+strings.Join(cmd, " ")]; ok {
		return out, nil
	}
	return f.execOut[name+":"+cmd[0]], nil
}

// setNodeProc stubs what a node reports about itself once booted —
// the vantage point a reservation may be derived from, and the only
// one that can tell a nested host's lie from a plain host's truth
// (#1466). Explicit in every test that needs it: a fake that served a
// plausible default /proc would hide exactly the bug under test.
func (f *fakeHost) setNodeProc(name string, cpu int, memKB int64) {
	var b strings.Builder
	for i := 0; i < cpu; i++ {
		fmt.Fprintf(&b, "processor\t: %d\nvendor_id\t: GenuineIntel\n\n", i)
	}
	f.execOut[name+":cat "+ProcCPUInfoPath] = b.String()
	f.execOut[name+":cat "+ProcMemInfoPath] = fmt.Sprintf("MemTotal:%15d kB\nMemFree:  1024 kB\n", memKB)
}
func (f *fakeHost) ClusterVMs(tenant, clusterName string) (Observed, error) {
	return Observed{}, nil
}

func testManager(f *fakeHost) *Manager {
	return &Manager{
		host:             f,
		k3sBinary:        func() ([]byte, error) { return []byte("k3s-binary-bytes"), nil },
		waitReadyTimeout: time.Second,
	}
}

func TestProvisionCPSequence(t *testing.T) {
	f := newFakeHost()
	m := testManager(f)

	ip, err := m.ProvisionCP("alice", "demo", IsolationVM, DesiredGroup{CPU: "2", Memory: "4GB", Disk: "40GB"}, []string{"203.0.113.10"})
	if err != nil {
		t.Fatalf("ProvisionCP: %v", err)
	}
	if ip != "10.166.11.5" {
		t.Fatalf("ip = %q", ip)
	}
	want := []string{
		"create alice-k8s-demo-cp cpu=2 mem=4GB disk=40GB role=control-plane",
		"wait alice-k8s-demo-cp",
		// Each push is preceded by its parent mkdir (#1442): Incus
		// answers Not Found for a missing parent, and these
		// directories do not exist in a fresh node image.
		"exec alice-k8s-demo-cp:mkdir -p " + filepath.Dir(K3sBinaryPath),
		"push alice-k8s-demo-cp:" + K3sBinaryPath + " mode=0755",
		"exec alice-k8s-demo-cp:mkdir -p " + filepath.Dir(bootstrapScriptPath),
		"push alice-k8s-demo-cp:" + bootstrapScriptPath + " mode=0755",
		"exec alice-k8s-demo-cp:sh " + bootstrapScriptPath,
	}
	assertCalls(t, f.calls, want)

	// The pushed script carries BOTH the VM IP and the external SAN.
	script := string(f.files["alice-k8s-demo-cp:"+bootstrapScriptPath])
	for _, san := range []string{"--tls-san 10.166.11.5", "--tls-san 203.0.113.10"} {
		if !strings.Contains(script, san) {
			t.Fatalf("server script missing %q", san)
		}
	}
}

func TestProvisionWorkerSequence(t *testing.T) {
	f := newFakeHost()
	// Shaped like a real k3s node-token — CA hash, separator,
	// credential, trailing newline — so byte-identity below means
	// the CA hash and the newline both survived the round trip
	// (#1446). Value is synthetic.
	const nodeToken = "K10aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899::server:0123456789abcdef\n"
	f.files["alice-k8s-demo-cp:"+NodeTokenPath] = []byte(nodeToken)
	m := testManager(f)

	err := m.ProvisionWorker("alice", "demo", IsolationVM,
		DesiredGroup{Name: "small", CPU: "2", Memory: "4GB", Disk: "40GB"},
		"alice-k8s-demo-small-1", "10.166.11.5")
	if err != nil {
		t.Fatalf("ProvisionWorker: %v", err)
	}
	want := []string{
		"read alice-k8s-demo-cp:" + NodeTokenPath,
		"create alice-k8s-demo-small-1 cpu=2 mem=4GB disk=40GB role=worker",
		"wait alice-k8s-demo-small-1",
		"exec alice-k8s-demo-small-1:mkdir -p " + filepath.Dir(K3sBinaryPath),
		"push alice-k8s-demo-small-1:" + K3sBinaryPath + " mode=0755",
		// The one that was actually failing in production: /etc/containarium
		// does not exist in a fresh image, so this push returned Not Found.
		"exec alice-k8s-demo-small-1:mkdir -p " + filepath.Dir(AgentTokenPath),
		"push alice-k8s-demo-small-1:" + AgentTokenPath + " mode=0600",
		"exec alice-k8s-demo-small-1:mkdir -p " + filepath.Dir(bootstrapScriptPath),
		"push alice-k8s-demo-small-1:" + bootstrapScriptPath + " mode=0755",
		"exec alice-k8s-demo-small-1:sh " + bootstrapScriptPath,
	}
	assertCalls(t, f.calls, want)

	// Byte-identical to what the CP has at NodeTokenPath — no
	// truncation, no transformation, newline intact (#1446).
	if got := string(f.files["alice-k8s-demo-small-1:"+AgentTokenPath]); got != nodeToken {
		t.Fatalf("token pushed = %q, want the CP's node-token byte-identical %q", got, nodeToken)
	}
	script := string(f.files["alice-k8s-demo-small-1:"+bootstrapScriptPath])
	if !strings.Contains(script, "--server https://10.166.11.5:6443") {
		t.Fatalf("agent script joins wrong server:\n%s", script)
	}

	// A CP whose token can't be read must fail BEFORE creating a VM.
	f2 := newFakeHost()
	f2.readErr = errors.New("no such file")
	if err := testManager(f2).ProvisionWorker("alice", "demo", IsolationVM, DesiredGroup{Name: "small"}, "alice-k8s-demo-small-1", "10.0.0.1"); err == nil {
		t.Fatal("worker provisioned without a join token")
	}
	for _, c := range f2.calls {
		if strings.HasPrefix(c, "create") {
			t.Fatalf("VM created despite missing token: %v", f2.calls)
		}
	}
}

func TestKubeconfigRewrites(t *testing.T) {
	f := newFakeHost()
	f.files["alice-k8s-demo-cp:"+KubeconfigPath] = []byte("clusters:\n- cluster:\n    server: https://127.0.0.1:6443\n")
	m := testManager(f)

	kc, err := m.Kubeconfig("alice", "demo", "203.0.113.10:30443")
	if err != nil {
		t.Fatalf("Kubeconfig: %v", err)
	}
	if !strings.Contains(kc, "server: https://203.0.113.10:30443") || strings.Contains(kc, "127.0.0.1") {
		t.Fatalf("kubeconfig not rewritten:\n%s", kc)
	}
}

func TestReadyNodesParsesKubectl(t *testing.T) {
	f := newFakeHost()
	f.execOut["alice-k8s-demo-cp:"+K3sBinaryPath] = "" +
		"alice-k8s-demo-cp        Ready    control-plane   5m    v1.33.4+k3s1\n" +
		"alice-k8s-demo-small-1   Ready    <none>          2m    v1.33.4+k3s1\n" +
		"alice-k8s-demo-small-2   NotReady <none>          10s   v1.33.4+k3s1\n"
	m := testManager(f)
	n, err := m.ReadyNodes("alice", "demo")
	if err != nil {
		t.Fatalf("ReadyNodes: %v", err)
	}
	if n != 2 {
		t.Fatalf("ReadyNodes = %d, want 2", n)
	}
}

func assertCalls(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("call sequence:\n  got  %q\n  want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call %d:\n  got  %q\n  want %q", i, got[i], want[i])
		}
	}
}

// The seam carries the isolation class end to end (#1429): CreateNode
// receives it verbatim, and the bootstrap script the node executes is
// the matching variant (kmsg shim only on the container path).
func TestProvisionCarriesIsolationThroughTheSeam(t *testing.T) {
	cases := []struct {
		name     string
		iso      Isolation
		wantShim bool
	}{
		{"vm nodes", IsolationVM, false},
		{"container nodes", IsolationContainer, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeHost()
			// #1448: a container-mode provision derives the worker's
			// containerd template from the CP's generated config, so the
			// fake CP must have one — its absence is a loud failure by design.
			f.files["alice-k8s-demo-cp:"+ContainerdGeneratedConfigPath] = []byte(
				"version = 3\n  enable_unprivileged_ports = true\n  enable_unprivileged_icmp = true\n")
			// The node must be able to answer what it observes about
			// itself: the reservation trigger asks it after boot (#1466).
			// These fixtures are an honest node — it sees its own limits.
			f.setNodeProc("alice-k8s-demo-cp", 2, 3906244)
			f.setNodeProc("alice-k8s-demo-small-1", 2, 3906244)
			m := testManager(f)

			if _, err := m.ProvisionCP("alice", "demo", tc.iso, DesiredGroup{CPU: "2", Memory: "4GB", Disk: "40GB"}, nil); err != nil {
				t.Fatalf("ProvisionCP: %v", err)
			}
			if got := f.isolations["alice-k8s-demo-cp"]; got != tc.iso {
				t.Fatalf("CP CreateNode isolation = %q, want %q", got, tc.iso)
			}
			cpScript := string(f.files["alice-k8s-demo-cp:"+bootstrapScriptPath])
			if strings.Contains(cpScript, "kmsg") != tc.wantShim {
				t.Fatalf("CP script kmsg shim = %v, want %v:\n%s", !tc.wantShim, tc.wantShim, cpScript)
			}

			f.files["alice-k8s-demo-cp:"+NodeTokenPath] = []byte("K10secret::token")
			err := m.ProvisionWorker("alice", "demo", tc.iso,
				DesiredGroup{Name: "small", CPU: "2", Memory: "4GB", Disk: "40GB"},
				"alice-k8s-demo-small-1", "10.166.11.5")
			if err != nil {
				t.Fatalf("ProvisionWorker: %v", err)
			}
			if got := f.isolations["alice-k8s-demo-small-1"]; got != tc.iso {
				t.Fatalf("worker CreateNode isolation = %q, want %q", got, tc.iso)
			}
			wScript := string(f.files["alice-k8s-demo-small-1:"+bootstrapScriptPath])
			if strings.Contains(wScript, "kmsg") != tc.wantShim {
				t.Fatalf("worker script kmsg shim = %v, want %v:\n%s", !tc.wantShim, tc.wantShim, wScript)
			}
		})
	}
}

// A container node whose host cannot honour its size must be refused
// BEFORE creation: creating it produces a node advertising capacity it
// does not have, which the scheduler and the autoscaler both believe
// (#1439, design Amendment 1).
func TestProvisionWorkerRefusesUnhonourableCapacity(t *testing.T) {
	f := newFakeHost()
	f.capacityError = errors.New("host observes 2 cpu but node was sized 8")
	f.files["alice-k8s-demo-cp:"+NodeTokenPath] = []byte("token")

	err := testManager(f).ProvisionWorker("alice", "demo", IsolationContainer,
		DesiredGroup{Name: "small", CPU: "8", Memory: "16GB", Disk: "40GB"},
		"alice-k8s-demo-small-1", "10.0.0.1")
	if err == nil {
		t.Fatal("provisioning must refuse a node the host cannot size truthfully")
	}
	for _, call := range f.calls {
		if strings.HasPrefix(call, "CreateNode") {
			t.Fatalf("node was created despite the capacity refusal: %v", f.calls)
		}
	}

	// The VM path is not subject to this check — a VM gets its own
	// kernel and reports its own size honestly.
	f2 := newFakeHost()
	f2.capacityError = errors.New("would refuse a container node")
	f2.files["alice-k8s-demo-cp:"+NodeTokenPath] = []byte("token")
	if err := testManager(f2).ProvisionWorker("alice", "demo", IsolationVM,
		DesiredGroup{Name: "small", CPU: "8", Memory: "16GB", Disk: "40GB"},
		"alice-k8s-demo-small-1", "10.0.0.1"); err != nil {
		t.Fatalf("VM provisioning must not consult the container capacity probe: %v", err)
	}
}

// Every path the cluster flow pushes to lives in a directory that does
// not exist in a fresh node image, and Incus answers "Not Found" for a
// missing parent. The parent must therefore be created BEFORE the push
// — ordering is the assertion, since a push that happens to succeed
// proves nothing about a fresh node (#1442).
func TestPushCreatesParentDirectoryFirst(t *testing.T) {
	f := newFakeHost()
	f.files["alice-k8s-demo-cp:"+NodeTokenPath] = []byte("token")

	if err := testManager(f).ProvisionWorker("alice", "demo", IsolationVM,
		DesiredGroup{Name: "small", CPU: "2", Memory: "4GB", Disk: "40GB"},
		"alice-k8s-demo-small-1", "10.0.0.1"); err != nil {
		t.Fatalf("provision: %v", err)
	}

	mkdirAt, pushAt := -1, -1
	for i, call := range f.calls {
		if mkdirAt < 0 && strings.Contains(call, "mkdir") && strings.Contains(call, "/etc/containarium") {
			mkdirAt = i
		}
		if pushAt < 0 && strings.Contains(call, "push ") && strings.Contains(call, AgentTokenPath) {
			pushAt = i
		}
	}
	if mkdirAt < 0 {
		t.Fatalf("no parent directory was created for %s: %v", AgentTokenPath, f.calls)
	}
	if pushAt < 0 {
		t.Fatalf("join token was never pushed: %v", f.calls)
	}
	if mkdirAt > pushAt {
		t.Fatalf("parent directory created AFTER the push (mkdir at %d, push at %d): %v", mkdirAt, pushAt, f.calls)
	}
}

// The worker's containerd template is derived by the daemon from the
// control plane's generated config and pushed BEFORE the bootstrap
// runs — a worker cannot produce that file itself until it has already
// joined (#1448). Ordering is the assertion: pushing it after the
// agent starts would be the same deadlock wearing a different hat.
func TestProvisionWorkerPushesContainerdTemplateBeforeBootstrap(t *testing.T) {
	f := newFakeHost()
	f.files["alice-k8s-demo-cp:"+NodeTokenPath] = []byte("K10hash::server:secret\n")
	f.files["alice-k8s-demo-cp:"+ContainerdGeneratedConfigPath] = []byte(
		"version = 3\n[plugins.'io.containerd.cri.v1.runtime']\n  enable_unprivileged_ports = true\n  enable_unprivileged_icmp = true\n")
	// The node must be able to answer what it observes about itself:
	// the reservation trigger asks it after boot (#1466). These
	// fixtures are an honest node — it sees its own limits.
	f.setNodeProc("alice-k8s-demo-cp", 2, 3906244)
	f.setNodeProc("alice-k8s-demo-small-1", 2, 3906244)

	if err := testManager(f).ProvisionWorker("alice", "demo", IsolationContainer,
		DesiredGroup{Name: "small", CPU: "2", Memory: "4GB", Disk: "40GB"},
		"alice-k8s-demo-small-1", "10.0.0.1"); err != nil {
		t.Fatalf("provision: %v", err)
	}

	got := string(f.files["alice-k8s-demo-small-1:"+ContainerdConfigTemplatePath])
	if !strings.Contains(got, "enable_unprivileged_ports = false") ||
		!strings.Contains(got, "enable_unprivileged_icmp = false") {
		t.Fatalf("worker did not receive a derived containerd template, got %q", got)
	}

	tmplAt, bootstrapAt := -1, -1
	for i, call := range f.calls {
		if tmplAt < 0 && strings.Contains(call, "push ") && strings.Contains(call, ContainerdConfigTemplatePath) {
			tmplAt = i
		}
		if bootstrapAt < 0 && strings.Contains(call, "exec ") && strings.Contains(call, bootstrapScriptPath) {
			bootstrapAt = i
		}
	}
	if tmplAt < 0 || bootstrapAt < 0 || tmplAt > bootstrapAt {
		t.Fatalf("template must be pushed before the bootstrap runs (tmpl %d, bootstrap %d): %v", tmplAt, bootstrapAt, f.calls)
	}
}

// A control plane whose generated config cannot be read must fail the
// worker loudly: shipping a node with pod sandboxes broken and a green
// bootstrap is exactly the silent failure #1448 warned against.
func TestProvisionWorkerFailsLoudlyWithoutCPContainerdConfig(t *testing.T) {
	f := newFakeHost()
	f.files["alice-k8s-demo-cp:"+NodeTokenPath] = []byte("K10hash::server:secret\n")
	// No CP containerd config on purpose.

	err := testManager(f).ProvisionWorker("alice", "demo", IsolationContainer,
		DesiredGroup{Name: "small", CPU: "2", Memory: "4GB", Disk: "40GB"},
		"alice-k8s-demo-small-1", "10.0.0.1")
	if err == nil {
		t.Fatal("provisioning must fail when the containerd template cannot be derived")
	}
	if !strings.Contains(err.Error(), "containerd") {
		t.Errorf("error does not name what failed: %v", err)
	}
}

// #1440 added KubeletArgs and its rendering, but nothing ever populated
// it — the reservation was dead code and the tests pinned rendering
// rather than wiring (#1452). These assert the WIRING: what the manager
// actually writes into the node's bootstrap script.
func TestProvisionWiresContainerKubeletArgs(t *testing.T) {
	f := newFakeHost()
	f.files["alice-k8s-demo-cp:"+NodeTokenPath] = []byte("K10hash::server:secret\n")
	f.files["alice-k8s-demo-cp:"+ContainerdGeneratedConfigPath] = []byte(
		"version = 3\n  enable_unprivileged_ports = true\n  enable_unprivileged_icmp = true\n")
	// The node must be able to answer what it observes about itself:
	// the reservation trigger asks it after boot (#1466). These
	// fixtures are an honest node — it sees its own limits.
	f.setNodeProc("alice-k8s-demo-cp", 2, 3906244)
	f.setNodeProc("alice-k8s-demo-small-1", 2, 3906244)
	m := testManager(f)

	if _, err := m.ProvisionCP("alice", "demo", IsolationContainer,
		DesiredGroup{CPU: "2", Memory: "4GB", Disk: "40GB"}, []string{"203.0.113.10"}); err != nil {
		t.Fatalf("ProvisionCP: %v", err)
	}
	cpScript := string(f.files["alice-k8s-demo-cp:"+bootstrapScriptPath])
	if !strings.Contains(cpScript, "KubeletInUserNamespace=true") {
		t.Errorf("control-plane script has no KubeletInUserNamespace gate:\n%s", cpScript)
	}

	if err := m.ProvisionWorker("alice", "demo", IsolationContainer,
		DesiredGroup{Name: "small", CPU: "2", Memory: "4GB", Disk: "40GB"},
		"alice-k8s-demo-small-1", "10.0.0.1"); err != nil {
		t.Fatalf("ProvisionWorker: %v", err)
	}
	workerScript := string(f.files["alice-k8s-demo-small-1:"+bootstrapScriptPath])
	if !strings.Contains(workerScript, "KubeletInUserNamespace=true") {
		t.Errorf("worker script has no KubeletInUserNamespace gate:\n%s", workerScript)
	}

	// The VM path must not acquire container-only kubelet flags.
	f2 := newFakeHost()
	f2.files["alice-k8s-demo-cp:"+NodeTokenPath] = []byte("K10hash::server:secret\n")
	m2 := testManager(f2)
	if _, err := m2.ProvisionCP("alice", "demo", IsolationVM,
		DesiredGroup{CPU: "2", Memory: "4GB", Disk: "40GB"}, []string{"203.0.113.10"}); err != nil {
		t.Fatalf("ProvisionCP(vm): %v", err)
	}
	if strings.Contains(string(f2.files["alice-k8s-demo-cp:"+bootstrapScriptPath]), "KubeletInUserNamespace") {
		t.Error("VM control-plane script carries a container-only kubelet gate")
	}
}

// A container node must not be handed a reservation inferred from the
// daemon host's /proc. Where lxcfs works the node sees its own limits,
// and such a reservation exceeds the node's entire capacity — kubelet
// rejects it and refuses to start, which is worse than an uncorrected
// allocatable (#1456, observed on the CI runner in run 11).
//
// Since #1466 this test also pins the environment it was implicitly
// assuming: the fixture is a node observing its own limits, and the
// assertion is that such a node gets no reservation. The complementary
// case — a node observing the outer host, which must get one — lives in
// TestContainerNodeReservationFollowsWhatTheNodeObserves.
func TestProvisionDoesNotReserveFromHostCapacity(t *testing.T) {
	f := newFakeHost()
	f.files["alice-k8s-demo-cp:"+NodeTokenPath] = []byte("K10hash::server:secret\n")
	f.files["alice-k8s-demo-cp:"+ContainerdGeneratedConfigPath] = []byte(
		"version = 3\n  enable_unprivileged_ports = true\n  enable_unprivileged_icmp = true\n")
	// The node must be able to answer what it observes about itself:
	// the reservation trigger asks it after boot (#1466). These
	// fixtures are an honest node — it sees its own limits.
	f.setNodeProc("alice-k8s-demo-cp", 2, 3906244)
	f.setNodeProc("alice-k8s-demo-small-1", 2, 3906244)
	m := testManager(f)

	if _, err := m.ProvisionCP("alice", "demo", IsolationContainer,
		DesiredGroup{CPU: "2", Memory: "4GB", Disk: "40GB"}, []string{"203.0.113.10"}); err != nil {
		t.Fatalf("ProvisionCP: %v", err)
	}
	script := string(f.files["alice-k8s-demo-cp:"+bootstrapScriptPath])
	if strings.Contains(script, "system-reserved") {
		t.Errorf("node was given a reservation inferred from the daemon host (#1456):\n%s", script)
	}
	// The gate that makes kubelet start at all must still be there.
	if !strings.Contains(script, "KubeletInUserNamespace=true") {
		t.Error("dropping the reservation also dropped the user-namespace gate")
	}
}

// Incus refuses to delete a running instance ("Instance is running"),
// so a node must be stopped first. The tenant container path has always
// done this (pkg/core/container/manager.go stops if running, then
// deletes); the cluster path did not, which meant scale-down could
// never remove a node and `cluster delete` left every instance of the
// cluster running on the host (#1475).
func TestDeleteNodeStopsBeforeDeleting(t *testing.T) {
	f := newFakeHost()
	m := NewManager(f, DefaultArtifactBase)

	if err := m.DeleteVM("alice-k8s-demo-small-1"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	var stopAt, deleteAt = -1, -1
	for i, c := range f.calls {
		switch c {
		case "stop alice-k8s-demo-small-1":
			stopAt = i
		case "delete alice-k8s-demo-small-1":
			deleteAt = i
		}
	}
	if stopAt < 0 {
		t.Fatalf("node was never stopped; Incus will refuse the delete:\n%v", f.calls)
	}
	if deleteAt < 0 || deleteAt < stopAt {
		t.Fatalf("delete must follow the stop, got %v", f.calls)
	}
}

// An already-stopped node reports an error from stop, and that must not
// prevent the delete — otherwise a node that was stopped by any other
// means becomes undeletable.
func TestDeleteNodeDeletesEvenWhenStopFails(t *testing.T) {
	f := newFakeHost()
	f.stopErr = errors.New("The instance is already stopped")
	m := NewManager(f, DefaultArtifactBase)

	if err := m.DeleteVM("alice-k8s-demo-small-1"); err != nil {
		t.Fatalf("a failing stop must not block the delete: %v", err)
	}
	found := false
	for _, c := range f.calls {
		if c == "delete alice-k8s-demo-small-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("delete was never attempted: %v", f.calls)
	}
}

// The delete's own error is what the caller must see — the autoscaler
// retries on it, and swallowing it would make a failed scale-down look
// like a successful one.
func TestDeleteNodeReturnsTheDeleteError(t *testing.T) {
	f := newFakeHost()
	f.deleteErr = errors.New("boom")
	m := NewManager(f, DefaultArtifactBase)

	if err := m.DeleteVM("alice-k8s-demo-small-1"); err == nil {
		t.Fatal("a failed delete must be reported, not swallowed")
	}
}

// #1466: the reservation's trigger. A container node gets a
// reservation only when it ACTUALLY misreports, established by asking
// the node itself after boot — never inferred from the daemon host's
// /proc, which is what #1456 got wrong in the other direction.
//
// The two environments are the whole point of the test: on a plain
// Incus host lxcfs works and the node sees its own limits, so any
// reservation is harmful (kubelet refuses a reservation exceeding
// capacity); on a nested host lxcfs masking does not reach the inner
// instance, the node sees the outer host, and without a reservation
// the scheduler and the autoscaler's fit simulation both believe a
// node four times its real size — so scale-up never triggers.
func TestContainerNodeReservationFollowsWhatTheNodeObserves(t *testing.T) {
	// The nested-host measurement from the design's Amendment 1 §2.
	const (
		nestedCPU   = 8
		nestedMemKB = 65841348
	)

	tests := []struct {
		name        string
		nodeCPU     int
		nodeMemKB   int64
		wantReserve bool
		wantArgs    []string
	}{
		{
			name:      "plain host: the node sees its own limits, so nothing is reserved",
			nodeCPU:   2,
			nodeMemKB: 3906244, // ~4GB, what a 4GB node reports where lxcfs works
		},
		{
			name:        "nested host: the node sees the outer host, so the gap is reserved",
			nodeCPU:     nestedCPU,
			nodeMemKB:   nestedMemKB,
			wantReserve: true,
			wantArgs: []string{
				fmt.Sprintf("--kubelet-arg=system-reserved=cpu=%d,memory=%d",
					nestedCPU-2, nestedMemKB*1024-4_000_000_000),
				"--kubelet-arg=enforce-node-allocatable=pods",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, role := range []string{"control-plane", "worker"} {
				t.Run(role, func(t *testing.T) {
					f := newFakeHost()
					f.files["alice-k8s-demo-cp:"+NodeTokenPath] = []byte("K10hash::server:secret\n")
					f.files["alice-k8s-demo-cp:"+ContainerdGeneratedConfigPath] = []byte(
						"version = 3\n  enable_unprivileged_ports = true\n  enable_unprivileged_icmp = true\n")

					node := "alice-k8s-demo-cp"
					if role == "worker" {
						node = "alice-k8s-demo-small-1"
						f.setNodeProc("alice-k8s-demo-cp", 2, 3906244)
					}
					f.setNodeProc(node, tt.nodeCPU, tt.nodeMemKB)
					m := testManager(f)

					if _, err := m.ProvisionCP("alice", "demo", IsolationContainer,
						DesiredGroup{CPU: "2", Memory: "4GB", Disk: "40GB"}, []string{"203.0.113.10"}); err != nil {
						t.Fatalf("ProvisionCP: %v", err)
					}
					if role == "worker" {
						if err := m.ProvisionWorker("alice", "demo", IsolationContainer,
							DesiredGroup{Name: "small", CPU: "2", Memory: "4GB", Disk: "40GB"},
							node, "10.0.0.1"); err != nil {
							t.Fatalf("ProvisionWorker: %v", err)
						}
					}

					script := string(f.files[node+":"+bootstrapScriptPath])
					if !tt.wantReserve {
						if strings.Contains(script, "system-reserved") {
							t.Errorf("node observing its own limits was given a reservation:\n%s", script)
						}
					}
					for _, want := range tt.wantArgs {
						if !strings.Contains(script, want) {
							t.Errorf("script is missing %q:\n%s", want, script)
						}
					}
					// Whatever the reservation, the gate without which
					// kubelet's ContainerManager never starts must stay.
					if !strings.Contains(script, "KubeletInUserNamespace=true") {
						t.Errorf("%s script lost the user-namespace gate:\n%s", role, script)
					}
				})
			}
		})
	}
}

// A VM node has its own kernel and reports honestly, so it must never
// be probed for a correction, let alone given one — the probe is an
// Exec into the node, and running it on the VM path would be both
// pointless and a behaviour change to the class this issue does not
// touch.
func TestVMNodeIsNeverProbedForCapacity(t *testing.T) {
	f := newFakeHost()
	f.files["alice-k8s-demo-cp:"+NodeTokenPath] = []byte("K10hash::server:secret\n")
	m := testManager(f)

	if _, err := m.ProvisionCP("alice", "demo", IsolationVM,
		DesiredGroup{CPU: "2", Memory: "4GB", Disk: "40GB"}, []string{"203.0.113.10"}); err != nil {
		t.Fatalf("ProvisionCP: %v", err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, ProcCPUInfoPath) || strings.Contains(c, ProcMemInfoPath) {
			t.Errorf("VM node was probed for observed capacity: %q", c)
		}
	}
	if strings.Contains(string(f.files["alice-k8s-demo-cp:"+bootstrapScriptPath]), "system-reserved") {
		t.Error("VM node was given a container-only reservation")
	}
}

// A node whose /proc cannot be read fails the provision rather than
// silently proceeding without a reservation. An unreadable /proc means
// the lie cannot be measured, not that there is no lie — and a node
// that quietly advertises four times its size is the exact failure
// (#1466) this trigger exists to prevent, with nothing to say so.
func TestContainerNodeUnreadableProcFailsClosed(t *testing.T) {
	f := newFakeHost()
	f.files["alice-k8s-demo-cp:"+NodeTokenPath] = []byte("K10hash::server:secret\n")
	m := testManager(f)
	// No setNodeProc: the node answers with nothing.

	_, err := m.ProvisionCP("alice", "demo", IsolationContainer,
		DesiredGroup{CPU: "2", Memory: "4GB", Disk: "40GB"}, []string{"203.0.113.10"})
	if err == nil {
		t.Fatal("provisioning succeeded with an unmeasurable node capacity; it must fail closed")
	}
	if !strings.Contains(err.Error(), "observed capacity") {
		t.Errorf("error should name what could not be established, got: %v", err)
	}
}

// The node is asked what it observes AFTER it is up — asking a node
// that has not booted cannot answer, and asking before create is the
// daemon-host inference #1456 removed.
func TestCapacityProbeHappensAfterWaitReady(t *testing.T) {
	f := newFakeHost()
	f.setNodeProc("alice-k8s-demo-cp", 8, 65841348)
	m := testManager(f)

	if _, err := m.ProvisionCP("alice", "demo", IsolationContainer,
		DesiredGroup{CPU: "2", Memory: "4GB", Disk: "40GB"}, []string{"203.0.113.10"}); err != nil {
		t.Fatalf("ProvisionCP: %v", err)
	}
	waitAt, probeAt, pushAt := -1, -1, -1
	for i, c := range f.calls {
		switch {
		case c == "wait alice-k8s-demo-cp":
			waitAt = i
		case strings.Contains(c, ProcCPUInfoPath):
			probeAt = i
		case strings.Contains(c, bootstrapScriptPath) && strings.HasPrefix(c, "push"):
			pushAt = i
		}
	}
	if waitAt < 0 || probeAt < 0 || pushAt < 0 {
		t.Fatalf("missing calls: wait=%d probe=%d push=%d in %v", waitAt, probeAt, pushAt, f.calls)
	}
	if !(waitAt < probeAt && probeAt < pushAt) {
		t.Errorf("probe must sit between WaitReady and the bootstrap push; got wait=%d probe=%d push=%d",
			waitAt, probeAt, pushAt)
	}
}
