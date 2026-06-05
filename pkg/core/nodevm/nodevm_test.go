package nodevm

import (
	"fmt"
	"strings"
	"testing"
)

func cpuSpec() Spec {
	return Spec{Name: "cpu-node", Kind: KindCPU, Pool: "cpu", CPU: 16, Memory: "64GiB", Disk: "200GiB", Sentinel: "sentinel:443"}
}
func gpuSpec() Spec {
	return Spec{Name: "gpu-node", Kind: KindGPU, Pool: "gpu", CPU: 8, Memory: "32GiB", GPUPCI: "0000:01:00.0", Sentinel: "sentinel:443"}
}

func TestValidate(t *testing.T) {
	if err := cpuSpec().Validate(); err != nil {
		t.Errorf("valid cpu spec rejected: %v", err)
	}
	if err := gpuSpec().Validate(); err != nil {
		t.Errorf("valid gpu spec rejected: %v", err)
	}
	bad := []Spec{
		{Kind: KindCPU, Pool: "cpu", CPU: 1, Memory: "1GiB", Sentinel: "s:1"},            // no name
		{Name: "n", Kind: "weird", Pool: "p", CPU: 1, Memory: "1GiB", Sentinel: "s:1"},   // bad kind
		{Name: "n", Kind: KindGPU, Pool: "gpu", CPU: 1, Memory: "1GiB", Sentinel: "s:1"}, // gpu w/o pci
		{Name: "n", Kind: KindCPU, Pool: "cpu", CPU: 0, Memory: "1GiB", Sentinel: "s:1"}, // cpu<=0
		{Name: "n", Kind: KindCPU, Pool: "cpu", CPU: 1, Sentinel: "s:1"},                 // no memory
		{Name: "n", Kind: KindCPU, Pool: "cpu", CPU: 1, Memory: "1GiB"},                  // no sentinel
		{Name: "n", Kind: KindCPU, CPU: 1, Memory: "1GiB", Sentinel: "s:1"},              // no pool
	}
	for i, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("bad spec %d should be rejected", i)
		}
	}
}

func TestSpotID(t *testing.T) {
	if got := gpuSpec().SpotID(); got != "gpu-node-gpu" {
		t.Errorf("SpotID = %q, want gpu-node-gpu", got)
	}
}

func TestLaunchArgs(t *testing.T) {
	got := strings.Join(launchArgs(cpuSpec()), " ")
	want := "launch images:ubuntu/24.04 cpu-node --vm -c limits.cpu=16 -c limits.memory=64GiB --device root,size=200GiB"
	if got != want {
		t.Errorf("launchArgs =\n %q\nwant\n %q", got, want)
	}
	// No disk → no --device root.
	s := cpuSpec()
	s.Disk = ""
	if strings.Contains(strings.Join(launchArgs(s), " "), "--device") {
		t.Errorf("no-disk spec should not emit --device root")
	}
}

func TestGPUDeviceArgs(t *testing.T) {
	got := strings.Join(gpuDeviceArgs("gpu-node", "0000:01:00.0"), " ")
	want := "config device add gpu-node gpu0 gpu pci=0000:01:00.0"
	if got != want {
		t.Errorf("gpuDeviceArgs = %q, want %q", got, want)
	}
}

func TestRenderBootstrap(t *testing.T) {
	script := RenderBootstrap(gpuSpec(), guestTokenPath)
	for _, want := range []string{
		"apt-get install -y -qq incus",
		"incus admin init --auto",
		"containarium service install",
		"--pool 'gpu'",
		"--spot-id 'gpu-node-gpu'",
		"--sentinel-addr 'sentinel:443'",
		"nvidia", // GPU node installs the driver
		"CONTAINARIUM_TUNNEL_TOKEN=\"$(cat /etc/containarium/tunnel.token)\"", // token from file, not argv
	} {
		if !strings.Contains(script, want) {
			t.Errorf("bootstrap missing %q in:\n%s", want, script)
		}
	}
	// CPU node must NOT install the nvidia driver.
	if strings.Contains(RenderBootstrap(cpuSpec(), guestTokenPath), "nvidia") {
		t.Errorf("cpu bootstrap should not install nvidia driver")
	}
	// The token value itself must never appear in the script.
	s := cpuSpec()
	s.TunnelToken = "SUPERSECRET"
	if strings.Contains(RenderBootstrap(s, guestTokenPath), "SUPERSECRET") {
		t.Errorf("token value leaked into bootstrap script")
	}
}

// fakeRunner records calls; "list" returns canned VM rows.
type fakeRunner struct {
	calls   []string
	listOut string
	failOn  string // substring of a joined call to fail
}

func (f *fakeRunner) Run(args ...string) (string, error) {
	joined := strings.Join(args, " ")
	f.calls = append(f.calls, joined)
	if f.failOn != "" && strings.Contains(joined, f.failOn) {
		return "", fmt.Errorf("forced failure on %q", f.failOn)
	}
	if strings.HasPrefix(joined, "list type=virtual-machine") {
		return f.listOut, nil
	}
	return "", nil
}
func (f *fakeRunner) calledWith(sub string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func TestProvision_CPUSequence(t *testing.T) {
	f := &fakeRunner{}
	m := NewManager(f, "") // no binary push
	m.waitAttempts = 1
	if _, err := m.Provision(cpuSpec()); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !f.calledWith("launch images:ubuntu/24.04 cpu-node --vm") {
		t.Error("did not launch the VM")
	}
	if f.calledWith("config device add") {
		t.Error("cpu node must NOT attach a GPU")
	}
	if !f.calledWith("exec cpu-node -- bash -c") {
		t.Error("did not run the in-guest bootstrap")
	}
}

func TestProvision_GPUAttachesCard(t *testing.T) {
	f := &fakeRunner{}
	m := NewManager(f, "")
	m.waitAttempts = 1
	if _, err := m.Provision(gpuSpec()); err != nil {
		t.Fatalf("Provision gpu: %v", err)
	}
	if !f.calledWith("config device add gpu-node gpu0 gpu pci=0000:01:00.0") {
		t.Error("gpu node must attach the GPU device")
	}
}

func TestProvision_IdempotentSkipsLaunch(t *testing.T) {
	f := &fakeRunner{listOut: "cpu-node,RUNNING\n"} // already exists
	m := NewManager(f, "")
	m.waitAttempts = 1
	if _, err := m.Provision(cpuSpec()); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if f.calledWith("launch ") {
		t.Error("existing VM should not be re-launched")
	}
	if !f.calledWith("exec cpu-node -- bash -c") {
		t.Error("should still re-run bootstrap to reconcile")
	}
}

func TestListAndDestroy(t *testing.T) {
	f := &fakeRunner{listOut: "cpu-node,RUNNING\ngpu-node,STOPPED\n"}
	m := NewManager(f, "")
	nodes, err := m.List()
	if err != nil || len(nodes) != 2 {
		t.Fatalf("List: %v len=%d", err, len(nodes))
	}
	if nodes[0].Name != "cpu-node" || nodes[0].State != "RUNNING" {
		t.Errorf("unexpected node[0]: %+v", nodes[0])
	}
	if err := m.Destroy("cpu-node"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if !f.calledWith("delete -f cpu-node") {
		t.Error("Destroy did not issue delete -f")
	}
}
