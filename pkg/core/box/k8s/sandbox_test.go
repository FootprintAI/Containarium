//go:build k8s

package k8s

import (
	"testing"

	box "github.com/footprintai/containarium/pkg/core/box"
)

// boxContainerEnv returns the agent-box container's env as a name→value map.
func boxContainerEnv(t *testing.T, boxMode string) map[string]string {
	t.Helper()
	sb := sandboxObject("tenant-x", box.BoxSpec{Ref: box.BoxRef{Tenant: "x"}, Image: "img", AutoStart: true}, false, memDefaults{}, podOptions{BoxMode: boxMode})
	containers := sb.Spec.SandboxBlueprint.PodTemplate.Spec.Containers
	if len(containers) != 1 {
		t.Fatalf("want 1 container, got %d", len(containers))
	}
	env := map[string]string{}
	for _, e := range containers[0].Env {
		env[e.Name] = e.Value
	}
	return env
}

// TestSandboxObjectBoxMode covers AGENTBOX_MODE injection: set for an explicit
// mode, absent when unset (the image then defaults to forced-command MCP).
func TestSandboxObjectBoxMode(t *testing.T) {
	if got := boxContainerEnv(t, "shell")["AGENTBOX_MODE"]; got != "shell" {
		t.Errorf("boxMode=shell: AGENTBOX_MODE = %q, want \"shell\"", got)
	}
	if _, ok := boxContainerEnv(t, "")["AGENTBOX_MODE"]; ok {
		t.Error("boxMode=\"\": AGENTBOX_MODE should not be set (image default is MCP)")
	}
}

// TestSandboxObjectRuntimeClass covers RuntimeClassName on the box PodSpec: set
// verbatim from Config.RuntimeClass so the pod lands on that runtime handler
// (e.g. "runsc" → a gVisor sandbox), and left nil when unconfigured so the pod
// keeps running on the cluster's default runtime. The nil case is the
// no-regression guard: every existing deployment leaves RuntimeClass empty.
func TestSandboxObjectRuntimeClass(t *testing.T) {
	tests := []struct {
		name         string
		runtimeClass string
		want         *string // nil = RuntimeClassName must be unset
	}{
		{name: "unset keeps the cluster default runtime", runtimeClass: "", want: nil},
		{name: "runsc selects the gVisor handler", runtimeClass: "runsc", want: strp("runsc")},
		{name: "arbitrary class is passed through verbatim", runtimeClass: "kata", want: strp("kata")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sb := sandboxObject("tenant-x", box.BoxSpec{Ref: box.BoxRef{Tenant: "x"}, Image: "img", AutoStart: true},
				false, memDefaults{}, podOptions{RuntimeClass: tc.runtimeClass})
			got := sb.Spec.SandboxBlueprint.PodTemplate.Spec.RuntimeClassName
			switch {
			case tc.want == nil && got != nil:
				t.Errorf("RuntimeClassName = %q, want unset", *got)
			case tc.want != nil && got == nil:
				t.Errorf("RuntimeClassName unset, want %q", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Errorf("RuntimeClassName = %q, want %q", *got, *tc.want)
			}
		})
	}
}

func strp(s string) *string { return &s }
