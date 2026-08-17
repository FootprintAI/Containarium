package cluster

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeHost records every VMHost call so tests assert the exact
// orchestration sequence — the part of the manager that matters.
type fakeHost struct {
	calls    []string
	files    map[string][]byte // "<vm>:<path>" → content
	execOut  map[string]string // "<vm>:<argv0...>" → stdout
	readErr  error
	capError error
}

func newFakeHost() *fakeHost {
	return &fakeHost{files: map[string][]byte{}, execOut: map[string]string{}}
}

func (f *fakeHost) record(format string, a ...any) {
	f.calls = append(f.calls, fmt.Sprintf(format, a...))
}

func (f *fakeHost) VMCapable() error { return f.capError }
func (f *fakeHost) CreateVM(spec NodeSpec) error {
	f.record("create %s cpu=%s mem=%s disk=%s role=%s", spec.Name, spec.CPU, spec.Memory, spec.Disk, spec.Labels[LabelClusterRole])
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

	ip, err := m.ProvisionCP("alice", "demo", DesiredGroup{CPU: "2", Memory: "4GB", Disk: "40GB"}, []string{"203.0.113.10"})
	if err != nil {
		t.Fatalf("ProvisionCP: %v", err)
	}
	if ip != "10.166.11.5" {
		t.Fatalf("ip = %q", ip)
	}
	want := []string{
		"create alice-k8s-demo-cp cpu=2 mem=4GB disk=40GB role=control-plane",
		"wait alice-k8s-demo-cp",
		"push alice-k8s-demo-cp:" + K3sBinaryPath + " mode=0755",
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

	err := m.ProvisionWorker("alice", "demo",
		DesiredGroup{Name: "small", CPU: "2", Memory: "4GB", Disk: "40GB"},
		"alice-k8s-demo-small-1", "10.166.11.5")
	if err != nil {
		t.Fatalf("ProvisionWorker: %v", err)
	}
	want := []string{
		"read alice-k8s-demo-cp:" + NodeTokenPath,
		"create alice-k8s-demo-small-1 cpu=2 mem=4GB disk=40GB role=worker",
		"wait alice-k8s-demo-small-1",
		"push alice-k8s-demo-small-1:" + K3sBinaryPath + " mode=0755",
		"push alice-k8s-demo-small-1:" + AgentTokenPath + " mode=0600",
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
	if err := testManager(f2).ProvisionWorker("alice", "demo", DesiredGroup{Name: "small"}, "alice-k8s-demo-small-1", "10.0.0.1"); err == nil {
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
