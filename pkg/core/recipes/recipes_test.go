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
	// The exposed port is the in-box auth proxy (:8080), not OpenHands directly.
	if len(r.Ports) != 1 || r.Ports[0].ContainerPort != 8080 {
		t.Errorf("agent-workspace should expose the in-box auth proxy on :8080; got %+v", r.Ports)
	}
	// post_start must run OpenHands Agent Canvas bound to localhost, persist
	// conversations in the box, chown the bind mounts, and stand up the in-box
	// basic-auth proxy (all validated live 2026-06-18).
	joined := strings.Join(r.PostStart, "\n")
	for _, want := range []string{
		"openhands/agent-canvas",
		"/opt/openhands-state", // conversations stored inside the box
		":U",                   // bind mount chowned to the non-root container user
		"127.0.0.1:8000:8000",  // OpenHands not directly reachable
		"caddy hash-password",  // password bcrypt-hashed at deploy
		"basic_auth",           // in-box auth proxy
		"ws_auth=",             // session-cookie handoff for seamless iframe auth
		"SameSite=None",        // cookie sent cross-origin from the embedded iframe
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("agent-workspace post_start missing %q", want)
		}
	}
	// The auth password is required (a box is never exposed without it).
	params := map[string]*pb.RecipeParam{}
	for _, p := range r.Parameters {
		params[p.Name] = p
	}
	if pw := params["auth_password"]; pw == nil {
		t.Fatal("agent-workspace should declare an auth_password parameter")
	} else {
		if !pw.Required {
			t.Error("auth_password must be required (box never exposed without auth)")
		}
		if pw.Type != "password" {
			t.Errorf("auth_password type: got %q want password", pw.Type)
		}
	}
	if params["openhands_version"] == nil || params["openhands_version"].Default == "" {
		t.Error("agent-workspace should pin openhands_version to a default tag")
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
