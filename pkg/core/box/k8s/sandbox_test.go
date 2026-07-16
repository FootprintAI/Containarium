//go:build k8s

package k8s

import (
	"testing"

	box "github.com/footprintai/containarium/pkg/core/box"
)

// boxContainerEnv returns the agent-box container's env as a name→value map.
func boxContainerEnv(t *testing.T, boxMode string) map[string]string {
	t.Helper()
	sb := sandboxObject("tenant-x", box.BoxSpec{Ref: box.BoxRef{Tenant: "x"}, Image: "img", AutoStart: true}, false, memDefaults{}, boxMode)
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
