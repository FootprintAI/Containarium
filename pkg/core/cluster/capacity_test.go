package cluster

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"text/template"

	"github.com/BurntSushi/toml"
)

// The containerd sysctl fix is DERIVED on the node from the config
// k3s itself generated — never a hand-written template. k3s's base
// template already declares [plugins.'io.containerd.cri.v1.runtime'],
// so a template that re-declares the table renders to invalid TOML,
// containerd cannot parse its config, and k3s never starts (#1444 —
// the container lane's control plane proved it). A golden alone did
// NOT catch that: a golden pins what we render, not whether it
// parses. These tests run the exact sed derivation the bootstrap
// embeds against a fixture shaped like a real generated config,
// render the result the way k3s renders a config template, and PARSE
// it with a TOML library.

const containerdGeneratedFixture = "testdata/containerd-generated-config.toml"

// renderAsK3sWould renders a config-v3.toml.tmpl body the way k3s
// does: as a text/template with "base" defined as the config k3s
// would itself generate.
func renderAsK3sWould(t *testing.T, tmplBody, base string) (string, error) {
	t.Helper()
	root := template.New("config-v3.toml.tmpl")
	template.Must(root.New("base").Parse(base))
	if _, err := root.Parse(tmplBody); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := root.Execute(&buf, nil); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// containerdConfig is the slice of containerd's config the fix cares
// about, decoded from the rendered TOML.
type containerdConfig struct {
	Version int `toml:"version"`
	Plugins struct {
		Runtime struct {
			EnableUnprivilegedPorts bool `toml:"enable_unprivileged_ports"`
			EnableUnprivilegedICMP  bool `toml:"enable_unprivileged_icmp"`
		} `toml:"io.containerd.cri.v1.runtime"`
	} `toml:"plugins"`
}

func TestDerivedContainerdTemplateIsValidTOML(t *testing.T) {
	base, err := os.ReadFile(containerdGeneratedFixture)
	if err != nil {
		t.Fatal(err)
	}
	// The exact derivation the bootstrap runs on the node.
	out, err := exec.Command("sed",
		append(ContainerdDeriveTemplateSedArgs(), containerdGeneratedFixture)...).Output()
	if err != nil {
		t.Fatalf("sed derivation failed: %v", err)
	}
	rendered, err := renderAsK3sWould(t, string(out), string(base))
	if err != nil {
		t.Fatalf("k3s could not render the derived template: %v", err)
	}
	var cfg containerdConfig
	if err := toml.Unmarshal([]byte(rendered), &cfg); err != nil {
		t.Fatalf("rendered template is invalid TOML — containerd would refuse it and k3s would never start: %v\n%s", err, rendered)
	}
	if cfg.Version != 3 {
		t.Errorf("version = %d, want 3 (k3s 1.33+ emits config version 3)", cfg.Version)
	}
	// The sysctl writes runc cannot perform in an unprivileged
	// container are exactly what these disable — leaving either true
	// kills every pod sandbox (design Amendment 1).
	if cfg.Plugins.Runtime.EnableUnprivilegedPorts {
		t.Error("enable_unprivileged_ports is still true after derivation")
	}
	if cfg.Plugins.Runtime.EnableUnprivilegedICMP {
		t.Error("enable_unprivileged_icmp is still true after derivation")
	}
	// The runtime table k3s's base template emits must be declared
	// exactly once — a second declaration is the #1444 regression.
	if n := strings.Count(rendered, "[plugins.'io.containerd.cri.v1.runtime']"); n != 1 {
		t.Errorf("runtime table declared %d times, want exactly 1:\n%s", n, rendered)
	}
}

// Prove the validator above can actually fail: feed it the exact
// broken form this issue removes — `{{ template "base" . }}` plus a
// re-declaration of the runtime table — and require the TOML parse to
// reject it. If a future TOML library upgrade started accepting
// duplicate tables, this test would flag that the valid-TOML check
// lost its teeth.
func TestValidatorRejectsRedeclaredBaseTable(t *testing.T) {
	base, err := os.ReadFile(containerdGeneratedFixture)
	if err != nil {
		t.Fatal(err)
	}
	broken := `{{ template "base" . }}

[plugins.'io.containerd.cri.v1.runtime']
  enable_unprivileged_ports = false
  enable_unprivileged_icmp = false
`
	// text/template renders the duplicate happily — the invalidity
	// only exists at the TOML layer, which is why a golden missed it.
	rendered, err := renderAsK3sWould(t, broken, string(base))
	if err != nil {
		t.Fatalf("template render: %v", err)
	}
	var cfg containerdConfig
	if err := toml.Unmarshal([]byte(rendered), &cfg); err == nil {
		t.Fatal("TOML parser accepted a re-declared runtime table — this suite would not have caught #1444")
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
func TestAgentScriptCarriesReservedArgs(t *testing.T) {
	container := RenderAgentScript(AgentBootstrap{
		ServerURL:   "https://10.0.0.1:6443",
		Isolation:   IsolationContainer,
		KubeletArgs: KubeletReservedArgs(Reserved{CPU: 6, MemoryBytes: 61_000_000_000}),
	})
	if !strings.Contains(container, "system-reserved=cpu=6") {
		t.Error("container agent script does not pass the kubelet reservation")
	}
	// The #1444 regression: a hand-written template re-declaring a
	// table k3s's base template already emits. It must never come back
	// in any bootstrap script.
	if strings.Contains(container, "{{ template") {
		t.Error("container agent script embeds a hand-written containerd template (#1444)")
	}
	if strings.Contains(container, "[plugins.") {
		t.Error("container agent script re-declares a containerd table k3s already emits (#1444)")
	}

	// This test used to assert the agent derived its containerd
	// template in-band (wait for the generated config -> sed ->
	// restart). That behaviour was #1448: an agent writes that config
	// only after it has joined, so the wait deadlocked. The inverse is
	// now pinned by TestAgentScriptDoesNotWaitForContainerdConfig, and
	// the daemon-side push it was replaced with by
	// TestProvisionWorkerPushesContainerdTemplateBeforeBootstrap. The
	// control plane keeps the in-band derivation, asserted by
	// TestServerScriptCarriesContainerdDerivation.

	vm := RenderAgentScript(AgentBootstrap{ServerURL: "https://10.0.0.1:6443", Isolation: IsolationVM})
	for _, unwanted := range []string{ContainerdConfigTemplatePath, "system-reserved", "enable_unprivileged"} {
		if strings.Contains(vm, unwanted) {
			t.Errorf("VM agent script contains container-only content %q", unwanted)
		}
	}
}

func TestServerScriptCarriesContainerdDerivation(t *testing.T) {
	container := RenderServerScript(ServerBootstrap{
		TLSSANs:   []string{"203.0.113.10"},
		Isolation: IsolationContainer,
	})
	for _, must := range []string{
		ContainerdGeneratedConfigPath,
		ContainerdConfigTemplatePath,
		"systemctl restart k3s.service",
		"was never generated", // the bounded wait fails loudly
	} {
		if !strings.Contains(container, must) {
			t.Errorf("container server script missing %q", must)
		}
	}
	if strings.Contains(container, "{{ template") {
		t.Error("container server script embeds a hand-written containerd template (#1444)")
	}
	if strings.Contains(container, "[plugins.") {
		t.Error("container server script re-declares a containerd table k3s already emits (#1444)")
	}
	enable := strings.Index(container, "systemctl enable --now k3s.service")
	derive := strings.Index(container, ContainerdGeneratedConfigPath)
	if enable == -1 || derive < enable {
		t.Error("containerd derivation must run after k3s is enabled")
	}

	// The VM path must stay exactly what it was.
	vm := RenderServerScript(ServerBootstrap{TLSSANs: []string{"203.0.113.10"}})
	for _, unwanted := range []string{ContainerdConfigTemplatePath, "enable_unprivileged", "systemctl restart"} {
		if strings.Contains(vm, unwanted) {
			t.Errorf("VM server script contains container-only content %q", unwanted)
		}
	}
}

// The host's /proc is what a container node will observe as its own
// capacity, so the daemon can predict the lie before creating anything.
func TestHostCapacity(t *testing.T) {
	cpu, mem, err := HostCapacity("testdata/proc-8cpu")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cpu != 8 {
		t.Errorf("cpu = %d, want 8 (processor lines in /proc/cpuinfo)", cpu)
	}
	if want := int64(65841348) * 1024; mem != want {
		t.Errorf("mem = %d, want %d (MemTotal kB → bytes)", mem, want)
	}
	if _, _, err := HostCapacity("testdata/does-not-exist"); err == nil {
		t.Error("missing /proc must be an error, not a zero capacity")
	}
}

func TestCheckNodeCapacity(t *testing.T) {
	// The real case from the design amendment: an 8-cpu/63GB host
	// hosting a 2-cpu/3GB node. Admitted — the gap is reservable.
	if err := CheckNodeCapacity(8, 64<<30, NodeSpec{CPU: "2", Memory: "3GB"}); err != nil {
		t.Errorf("host larger than the node must be admitted: %v", err)
	}
	// A host that cannot honour the size is refused, and the refusal
	// names the mismatch rather than saying "unsupported".
	err := CheckNodeCapacity(2, 2_000_000_000, NodeSpec{CPU: "8", Memory: "16GB"})
	if err == nil {
		t.Fatal("host smaller than the requested node size must be refused")
	}
	if !strings.Contains(err.Error(), "8") || !strings.Contains(err.Error(), "2") {
		t.Errorf("refusal does not name the observed/requested mismatch: %v", err)
	}
	if !errors.Is(err, ErrContainerNodesUnsupported) {
		t.Errorf("refusal should carry the container-node sentinel: %v", err)
	}
}

// A worker cannot derive its own containerd template: k3s agent writes
// config.toml only after it has retrieved configuration from the
// server, so a bootstrap that waits for that file blocks on something
// downstream of the startup it is blocking (#1448, observed in the
// container lane's run 8). The control plane has no such problem — k3s
// server starts containerd immediately — so only the agent path changes.
func TestAgentScriptDoesNotWaitForContainerdConfig(t *testing.T) {
	container := RenderAgentScript(AgentBootstrap{
		ServerURL: "https://10.0.0.1:6443",
		Isolation: IsolationContainer,
	})
	for _, forbidden := range []string{
		ContainerdGeneratedConfigPath, // the file the agent cannot produce yet
		"was never generated",         // the wait's failure message
		"systemctl restart",           // the restart that followed the wait
	} {
		if strings.Contains(container, forbidden) {
			t.Errorf("agent script still derives containerd config in-band (%q) — it deadlocks (#1448)", forbidden)
		}
	}

	// The control-plane path keeps its proven behaviour.
	server := RenderServerScript(ServerBootstrap{TLSSANs: []string{"203.0.113.10"}, Isolation: IsolationContainer})
	for _, want := range []string{ContainerdGeneratedConfigPath, "systemctl restart k3s.service"} {
		if !strings.Contains(server, want) {
			t.Errorf("server script lost its containerd derivation (%q)", want)
		}
	}
}

// The worker's template is instead derived by the daemon from the
// control plane's already-generated config and pushed before the agent
// starts. Deriving in Go keeps the failure loud: a config that cannot
// be flipped is an error, not a silently-unmodified template.
func TestDeriveContainerdTemplate(t *testing.T) {
	generated := "version = 3\n\n[plugins.'io.containerd.cri.v1.runtime']\n" +
		"  enable_unprivileged_ports = true\n  enable_unprivileged_icmp = true\n"

	got, err := DeriveContainerdTemplate([]byte(generated))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"enable_unprivileged_ports = false", "enable_unprivileged_icmp = false"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("derived template missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(string(got), "= true") {
		t.Errorf("derived template still enables a toggle:\n%s", got)
	}

	// A config missing a toggle entirely must ERROR rather than return
	// a template that silently leaves pods broken — the whole point of
	// #1444's loud failure, preserved on the new path.
	if _, err := DeriveContainerdTemplate([]byte("version = 3\n")); err == nil {
		t.Error("a config without the toggles must be an error, not a silent pass-through")
	}
}
