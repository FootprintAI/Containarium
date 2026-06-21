package skills

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/footprintai/containarium/pkg/core/catalogsig"
)

const extSkillYAML = `
skills:
  - id: ext-skill
    recipe_id: agent-runtime
    system_prompt: external
    allowed_scopes: [security:read]
`

// TestLoadDirVerified covers the optional provenance check (#648): a good
// signature loads, a missing or tampered one fails closed, and a nil verifier
// is the unchanged unsigned path.
func TestLoadDirVerified(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := catalogsig.NewVerifier(pub)

	writeCatalog := func(dir string, signWith ed25519.PrivateKey) {
		path := filepath.Join(dir, "ext.yaml")
		if err := os.WriteFile(path, []byte(extSkillYAML), 0o600); err != nil {
			t.Fatal(err)
		}
		if signWith != nil {
			sig := ed25519.Sign(signWith, []byte(extSkillYAML))
			if err := os.WriteFile(path+catalogsig.SigSuffix, []byte(base64.StdEncoding.EncodeToString(sig)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run("good signature loads", func(t *testing.T) {
		dir := t.TempDir()
		writeCatalog(dir, priv)
		m := New()
		if err := m.LoadDirVerified(dir, v); err != nil {
			t.Fatalf("LoadDirVerified good sig: %v", err)
		}
		if _, err := m.Get("ext-skill"); err != nil {
			t.Error("signed external skill not merged")
		}
	})

	t.Run("missing signature fails", func(t *testing.T) {
		dir := t.TempDir()
		writeCatalog(dir, nil) // no .sig
		m := New()
		if err := m.LoadDirVerified(dir, v); err == nil {
			t.Fatal("expected unsigned file to fail in require-signed mode")
		}
		if _, err := m.Get("ext-skill"); err == nil {
			t.Error("unsigned skill must not be merged")
		}
	})

	t.Run("tampered payload fails", func(t *testing.T) {
		dir := t.TempDir()
		writeCatalog(dir, priv)
		// Mutate the catalog after signing.
		if err := os.WriteFile(filepath.Join(dir, "ext.yaml"), []byte(extSkillYAML+"\n# tampered\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		m := New()
		if err := m.LoadDirVerified(dir, v); err == nil {
			t.Fatal("expected tampered file to fail verification")
		}
	})

	t.Run("nil verifier loads unsigned", func(t *testing.T) {
		dir := t.TempDir()
		writeCatalog(dir, nil)
		m := New()
		if err := m.LoadDirVerified(dir, nil); err != nil {
			t.Fatalf("nil verifier should load unsigned: %v", err)
		}
		if _, err := m.Get("ext-skill"); err != nil {
			t.Error("nil-verifier path should merge unsigned skill")
		}
	})
}

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

	// The generic code-review skill ships in OSS and must be well-formed.
	cr, err := m.Get("code-review")
	if err != nil {
		t.Fatalf("code-review skill missing: %v", err)
	}
	if cr.GetRecipeId() != "agent-runtime" {
		t.Errorf("code-review recipe_id = %q, want agent-runtime", cr.GetRecipeId())
	}
	if cr.SystemPrompt == "" {
		t.Error("code-review has empty system_prompt")
	}
	if len(cr.AllowedScopes) == 0 {
		t.Error("code-review declares no allowed_scopes")
	}
	// Provider-agnostic: no model pinned, so it runs on whatever engine the
	// box's gateway provider selects.
	if cr.Model != "" {
		t.Errorf("code-review should not pin a model (provider-agnostic), got %q", cr.Model)
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
