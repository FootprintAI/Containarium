package skills

import "testing"

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
