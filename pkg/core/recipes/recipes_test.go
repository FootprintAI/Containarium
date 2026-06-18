package recipes

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestEmbeddedCatalogLoads(t *testing.T) {
	m := New()
	if err := m.LoadEmbedded(); err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if len(m.List()) == 0 {
		t.Fatal("embedded catalog is empty")
	}
	for _, id := range []string{"ollama", "llamacpp"} {
		r, err := m.Get(id)
		if err != nil {
			t.Errorf("expected built-in recipe %q: %v", id, err)
			continue
		}
		if r.Image == "" {
			t.Errorf("recipe %q has empty image", id)
		}
		if !r.RequiresGpu {
			t.Errorf("recipe %q expected requires_gpu=true", id)
		}
	}
}

func TestAgentWorkspaceRecipe(t *testing.T) {
	m := New()
	if err := m.LoadEmbedded(); err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	r, err := m.Get("agent-workspace")
	if err != nil {
		t.Fatalf("expected built-in recipe agent-workspace: %v", err)
	}
	if r.RequiresGpu {
		t.Error("agent-workspace should not require a GPU")
	}
	// The web chat UI must be exposed as a subdomain so chat + preview are
	// reachable in the browser.
	if len(r.Ports) != 1 || r.Ports[0].ContainerPort != 3000 {
		t.Errorf("agent-workspace should expose the OpenHands web UI on :3000; got %+v", r.Ports)
	}
	// post_start must run OpenHands, persist sessions in the box, and wire the
	// container engine socket for its runtime sandbox.
	joined := strings.Join(r.PostStart, "\n")
	for _, want := range []string{
		"all-hands-ai/openhands",
		"/opt/openhands-state", // conversations stored inside the box
		"podman.socket",
		"-p 3000:3000",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("agent-workspace post_start missing %q", want)
		}
	}
	// The API key is an optional, password-typed parameter (spike delivery);
	// the model is operator-overridable.
	params := map[string]*pb.RecipeParam{}
	for _, p := range r.Parameters {
		params[p.Name] = p
	}
	key := params["anthropic_api_key"]
	if key == nil {
		t.Fatal("agent-workspace should declare an anthropic_api_key parameter")
	}
	if key.Required {
		t.Error("anthropic_api_key should be optional (blank → set in OpenHands UI)")
	}
	if key.Type != "password" {
		t.Errorf("anthropic_api_key type: got %q want password", key.Type)
	}
	if params["llm_model"] == nil {
		t.Error("agent-workspace should declare an llm_model parameter")
	}
}

func TestGetUnknown(t *testing.T) {
	m := New()
	_ = m.LoadEmbedded()
	if _, err := m.Get("does-not-exist"); err == nil {
		t.Fatal("expected error for unknown recipe")
	}
}

func TestLoadRejectsMissingImage(t *testing.T) {
	m := New()
	err := m.LoadFromBytes([]byte("recipes:\n  - id: bad\n"))
	if err == nil {
		t.Fatal("expected error for recipe missing image")
	}
}

func TestLoadRejectsDuplicateID(t *testing.T) {
	m := New()
	yaml := "recipes:\n" +
		"  - id: dup\n    image: a\n" +
		"  - id: dup\n    image: b\n"
	if err := m.LoadFromBytes([]byte(yaml)); err == nil {
		t.Fatal("expected duplicate-id error")
	}
}

func TestLoadRejectsBadPort(t *testing.T) {
	m := New()
	yaml := "recipes:\n  - id: x\n    image: a\n    ports:\n      - container_port: 0\n        subdomain: s\n"
	if err := m.LoadFromBytes([]byte(yaml)); err == nil {
		t.Fatal("expected invalid-port error")
	}
}

func TestResolveParametersDefaultsAndRequired(t *testing.T) {
	r := &pb.Recipe{
		Id: "r",
		Parameters: []*pb.RecipeParam{
			{Name: "model", Default: "llama3"},
			{Name: "token", Required: true},
		},
	}

	// Missing required → error.
	if _, err := ResolveParameters(r, map[string]string{}); err == nil {
		t.Fatal("expected error when required parameter missing")
	}

	// Override applied, default kept.
	got, err := ResolveParameters(r, map[string]string{"token": "abc", "model": "qwen"})
	if err != nil {
		t.Fatalf("ResolveParameters: %v", err)
	}
	if got["model"] != "qwen" {
		t.Errorf("model override: got %q want qwen", got["model"])
	}
	if got["token"] != "abc" {
		t.Errorf("token: got %q want abc", got["token"])
	}

	// Default used when override blank.
	got, err = ResolveParameters(r, map[string]string{"token": "abc"})
	if err != nil {
		t.Fatalf("ResolveParameters: %v", err)
	}
	if got["model"] != "llama3" {
		t.Errorf("model default: got %q want llama3", got["model"])
	}
}

func TestParamEnvName(t *testing.T) {
	if got := ParamEnvName("hf_repo"); got != "CONTAINARIUM_PARAM_HF_REPO" {
		t.Errorf("ParamEnvName: got %q", got)
	}
}
