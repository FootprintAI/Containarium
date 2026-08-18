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
func (f *fakeHost) Start(name string) error  { f.record("start %s", name); return nil }
func (f *fakeHost) Delete(name string) error { f.record("delete %s", name); return nil }
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
	return f.execOut[name+":"+cmd[0]], nil
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
	f.files["alice-k8s-demo-cp:"+NodeTokenPath] = []byte("K10secret::token")
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

	if got := string(f.files["alice-k8s-demo-small-1:"+AgentTokenPath]); got != "K10secret::token" {
		t.Fatalf("token pushed = %q", got)
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
