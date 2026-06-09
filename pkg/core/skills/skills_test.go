package skills

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedCatalogLoads(t *testing.T) {
	m := GetDefault()
	all := m.List()
	if len(all) == 0 {
		t.Fatal("embedded skills catalog is empty")
	}

	// The neutral reference skill must be present and well-formed.
	hello, err := m.Get("hello-agent")
	if err != nil {
		t.Fatalf("hello-agent reference skill missing: %v", err)
	}
	if hello.GetRecipeId() != "agent-runtime" {
		t.Errorf("hello-agent box = %q, want recipe_id agent-runtime", hello.GetRecipeId())
	}
	if hello.SystemPrompt == "" {
		t.Error("hello-agent has empty system_prompt")
	}
	if len(hello.AllowedScopes) == 0 {
		t.Error("hello-agent declares no allowed_scopes")
	}
}

func TestValidateRejectsBadManifests(t *testing.T) {
	cases := map[string]string{
		"missing recipe_id": `
skills:
  - id: x
    system_prompt: hi
    allowed_scopes: [containers:read]
`,
		"missing system_prompt": `
skills:
  - id: x
    recipe_id: agent-runtime
    allowed_scopes: [containers:read]
`,
		"no scopes": `
skills:
  - id: x
    recipe_id: agent-runtime
    system_prompt: hi
    allowed_scopes: []
`,
		"unknown scope": `
skills:
  - id: x
    recipe_id: agent-runtime
    system_prompt: hi
    allowed_scopes: [containers:teleport]
`,
		"duplicate id": `
skills:
  - id: x
    recipe_id: agent-runtime
    system_prompt: hi
    allowed_scopes: [containers:read]
  - id: x
    recipe_id: agent-runtime
    system_prompt: hi
    allowed_scopes: [containers:read]
`,
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if err := New().LoadFromBytes([]byte(yaml)); err == nil {
				t.Errorf("expected load error for %q, got nil", name)
			}
		})
	}
}

func TestLoadDirMerges(t *testing.T) {
	const base = `
skills:
  - id: a
    recipe_id: agent-runtime
    system_prompt: hi
    allowed_scopes: [containers:read]
`
	m := New()
	if err := m.LoadFromBytes([]byte(base)); err != nil {
		t.Fatalf("base load: %v", err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ext.yaml"), []byte(`
skills:
  - id: ext-skill
    recipe_id: agent-runtime
    system_prompt: external
    allowed_scopes: [security:read]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if _, err := m.Get("a"); err != nil {
		t.Error("base skill lost after merge")
	}
	if _, err := m.Get("ext-skill"); err != nil {
		t.Error("external skill not merged")
	}
}

func TestLoadDirRejectsCollisionAndAllowsMissing(t *testing.T) {
	m := New()
	_ = m.LoadFromBytes([]byte("skills:\n  - id: dup\n    recipe_id: agent-runtime\n    system_prompt: x\n    allowed_scopes: [containers:read]\n"))

	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "dup.yaml"), []byte("skills:\n  - id: dup\n    recipe_id: agent-runtime\n    system_prompt: y\n    allowed_scopes: [containers:read]\n"), 0o600)
	if err := m.LoadDir(dir); err == nil {
		t.Error("expected collision error for duplicate id")
	}

	if err := m.LoadDir(filepath.Join(dir, "does-not-exist")); err != nil {
		t.Errorf("missing dir should be a no-op, got %v", err)
	}
}

func TestValidateAcceptsGoodManifest(t *testing.T) {
	const good = `
skills:
  - id: ok
    name: OK
    recipe_id: agent-runtime
    system_prompt: do the thing
    allowed_scopes: [containers:read, routes:read]
    allowed_peers: []
    agent_card:
      id: ok
      capabilities: [echo]
`
	m := New()
	if err := m.LoadFromBytes([]byte(good)); err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	s, err := m.Get("ok")
	if err != nil {
		t.Fatalf("get ok: %v", err)
	}
	if got := len(s.AllowedScopes); got != 2 {
		t.Errorf("allowed_scopes len = %d, want 2", got)
	}
	if s.AgentCard == nil || s.AgentCard.Id != "ok" {
		t.Error("agent_card not decoded")
	}
}
