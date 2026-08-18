package cluster

import (
	"strings"
	"testing"
)

// The containerd template is what turns "every pod sandbox fails" into
// a working node (design Amendment 1, verified live). These tests pin
// the two settings that matter and the fact that the VM path renders
// nothing at all.
func TestContainerdConfigTemplate(t *testing.T) {
	tmpl := ContainerdConfigTemplate()
	for _, want := range []string{
		"[plugins.'io.containerd.cri.v1.runtime']",
		"enable_unprivileged_ports = false",
		"enable_unprivileged_icmp = false",
	} {
		if !strings.Contains(tmpl, want) {
			t.Errorf("template missing %q:\n%s", want, tmpl)
		}
	}
	// The sysctl writes runc cannot perform in an unprivileged
	// container are exactly what these disable — a template that
	// re-enables them would restore the failure.
	if strings.Contains(tmpl, "= true") {
		t.Errorf("template enables an unprivileged-port/icmp sysctl:\n%s", tmpl)
	}
}

func TestContainerdConfigTemplatePath(t *testing.T) {
	// containerd config version 3 (k3s 1.33+) reads config-v3.toml.tmpl.
	if got := ContainerdConfigTemplatePath; !strings.HasSuffix(got, "config-v3.toml.tmpl") {
		t.Fatalf("template path %q does not target the v3 template", got)
	}
}

// Allocatable must come from the size the daemon asked for, never from
// cadvisor: /proc in a container node reports the outer host's CPU and
// memory (design Amendment 1 — a 2-cpu/3GB node advertised 8 cpu/63GB).
func TestReservedResources(t *testing.T) {
	tests := []struct {
		name        string
		observedCPU int
		observedMem int64
		spec        NodeSpec
		wantCPU     int
		wantMem     int64
		wantErr     bool
	}{
		{
			name:        "host bigger than the node: reserve the difference",
			observedCPU: 8, observedMem: 64 << 30,
			spec:    NodeSpec{CPU: "2", Memory: "3GB"},
			wantCPU: 6, wantMem: 64<<30 - 3_000_000_000,
		},
		{
			name:        "observed equals requested: reserve nothing",
			observedCPU: 2, observedMem: 3_000_000_000,
			spec:    NodeSpec{CPU: "2", Memory: "3GB"},
			wantCPU: 0, wantMem: 0,
		},
		{
			name:        "observed smaller than requested: never negative, and say so",
			observedCPU: 2, observedMem: 2_000_000_000,
			spec:    NodeSpec{CPU: "4", Memory: "8GB"},
			wantErr: true,
		},
		{
			name:        "unparseable size is an error, not a silent zero",
			observedCPU: 8, observedMem: 64 << 30,
			spec:    NodeSpec{CPU: "many", Memory: "3GB"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReservedResources(tt.observedCPU, tt.observedMem, tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.CPU != tt.wantCPU || got.MemoryBytes != tt.wantMem {
				t.Fatalf("reserved = {cpu:%d mem:%d}, want {cpu:%d mem:%d}",
					got.CPU, got.MemoryBytes, tt.wantCPU, tt.wantMem)
			}
		})
	}
}

// The kubelet args are the mechanism that makes allocatable truthful.
func TestKubeletReservedArgs(t *testing.T) {
	args := KubeletReservedArgs(Reserved{CPU: 6, MemoryBytes: 61_000_000_000})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "system-reserved") {
		t.Fatalf("args do not reserve resources: %v", args)
	}
	if !strings.Contains(joined, "cpu=6") {
		t.Fatalf("args do not reserve the CPU difference: %v", args)
	}
	// Nothing to reserve must produce no args at all — a node whose
	// host matches its size gets the stock kubelet.
	if got := KubeletReservedArgs(Reserved{}); len(got) != 0 {
		t.Fatalf("zero reservation produced args: %v", got)
	}
}

// The template and the reserved args only matter if the node actually
// receives them, so pin the wiring, not just the pure functions.
func TestAgentScriptCarriesTemplateAndReservedArgs(t *testing.T) {
	container := RenderAgentScript(AgentBootstrap{
		ServerURL:   "https://10.0.0.1:6443",
		Isolation:   IsolationContainer,
		KubeletArgs: KubeletReservedArgs(Reserved{CPU: 6, MemoryBytes: 61_000_000_000}),
	})
	if !strings.Contains(container, ContainerdConfigTemplatePath) {
		t.Error("container agent script does not write the containerd template")
	}
	if !strings.Contains(container, "enable_unprivileged_ports = false") {
		t.Error("container agent script does not disable the unprivileged-port sysctl")
	}
	if !strings.Contains(container, "system-reserved=cpu=6") {
		t.Error("container agent script does not pass the kubelet reservation")
	}

	// The VM path must stay exactly what it was: no template, no args,
	// no behaviour bought with a change to the other isolation class.
	vm := RenderAgentScript(AgentBootstrap{ServerURL: "https://10.0.0.1:6443", Isolation: IsolationVM})
	for _, unwanted := range []string{ContainerdConfigTemplatePath, "system-reserved", "enable_unprivileged"} {
		if strings.Contains(vm, unwanted) {
			t.Errorf("VM agent script contains container-only content %q", unwanted)
		}
	}
}
