package skills

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/footprintai/containarium/pkg/core/catalogsig"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
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

	// deploy-branch provisions a fresh box from a git ref and must declare
	// the write scopes it needs to create the box and SSH into it.
	deploy, err := m.Get("deploy-branch")
	if err != nil {
		t.Fatalf("deploy-branch skill missing: %v", err)
	}
	if deploy.GetRecipeId() != "agent-runtime" {
		t.Errorf("deploy-branch recipe_id = %q, want agent-runtime", deploy.GetRecipeId())
	}
	if deploy.SystemPrompt == "" {
		t.Error("deploy-branch has empty system_prompt")
	}
	hasScope := func(scopes []string, want string) bool {
		for _, s := range scopes {
			if s == want {
				return true
			}
		}
		return false
	}
	requireScope := func(scopes []string, want string) {
		t.Helper()
		if !hasScope(scopes, want) {
			t.Errorf("deploy-branch missing expected scope %q, got %v", want, scopes)
		}
	}
	requireScope(deploy.AllowedScopes, "containers:write")
	requireScope(deploy.AllowedScopes, "ssh:write")
	// deploy-branch deliberately does NOT request routes:write: AddRoute
	// requires RoleAdmin unconditionally (see
	// TestAddRoute_RejectsScopeOnlyToken, internal/server), and a skill
	// token is minted with scopes only, never a role — so routes:write on a
	// skill manifest would be a scope that can never actually be exercised.
	// Locking this in as a regression guard: if this starts failing because
	// someone re-added routes:write, the authorization gap needs to be
	// fixed first (see the skill's comment in skills.yaml), not just this
	// assertion deleted.
	if hasScope(deploy.AllowedScopes, "routes:write") {
		t.Error("deploy-branch requests routes:write, but AddRoute requires RoleAdmin unconditionally and skill tokens are never granted roles — this scope can never be exercised (see skills.yaml comment)")
	}

	// verify-endpoint drives a live URL with a browser, so it declares its
	// own browser-capable box rather than the plain agent-runtime one.
	verify, err := m.Get("verify-endpoint")
	if err != nil {
		t.Fatalf("verify-endpoint skill missing: %v", err)
	}
	if verify.GetRecipeId() != "agent-runtime-browser" {
		t.Errorf("verify-endpoint recipe_id = %q, want agent-runtime-browser", verify.GetRecipeId())
	}
	if verify.SystemPrompt == "" {
		t.Error("verify-endpoint has empty system_prompt")
	}
	if len(verify.AllowedScopes) == 0 {
		t.Error("verify-endpoint declares no allowed_scopes")
	}
}

// TestDiffCrewSkillsDeclareOutputSchema (#2002): diff-drafter and diff-reviewer
// declare the JSON Schema of the artifact they emit, so the in-box runtime can
// hand it to the engine's structured-output mechanism instead of asking for the
// shape in prose. The schema must be the one the system prompt describes — an
// object with the files list plus the skill's own summary fields — otherwise
// enforcement and instruction disagree and the model can satisfy at most one.
func TestDiffCrewSkillsDeclareOutputSchema(t *testing.T) {
	type jsonSchema struct {
		Type                 string                     `json:"type"`
		Required             []string                   `json:"required"`
		Properties           map[string]json.RawMessage `json:"properties"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
	}
	cases := []struct {
		id       string
		required []string
	}{
		{"diff-drafter", []string{"files", "summary"}},
		{"diff-reviewer", []string{"files", "drafter_summary", "review_notes"}},
	}
	m := GetDefault()
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			sk, err := m.Get(tc.id)
			if err != nil {
				t.Fatalf("%s missing: %v", tc.id, err)
			}
			raw := sk.GetAgentCard().GetOutputSchemaJson()
			if raw == "" {
				t.Fatalf("%s declares no agent_card.output_schema_json; nothing for the runtime to enforce", tc.id)
			}
			var schema jsonSchema
			if err := json.Unmarshal([]byte(raw), &schema); err != nil {
				t.Fatalf("%s output_schema_json is not a JSON object: %v", tc.id, err)
			}
			if schema.Type != "object" {
				t.Errorf("%s output schema type = %q, want object", tc.id, schema.Type)
			}
			for _, field := range tc.required {
				if !slices.Contains(schema.Required, field) {
					t.Errorf("%s output schema does not require %q (required = %v)", tc.id, field, schema.Required)
				}
				if _, ok := schema.Properties[field]; !ok {
					t.Errorf("%s output schema has no property %q", tc.id, field)
				}
			}
			// The prompt says "exactly this shape": the schema must close the
			// object, or a stray key is schema-valid and the shape is not
			// actually enforced.
			if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
				t.Errorf("%s output schema must set additionalProperties: false", tc.id)
			}
			// files is a list of {path, content}, whole-file content (cloud#1738).
			var files jsonSchema
			if err := json.Unmarshal(schema.Properties["files"], &struct {
				Type  string      `json:"type"`
				Items *jsonSchema `json:"items"`
			}{Items: &files}); err != nil {
				t.Fatalf("%s files property: %v", tc.id, err)
			}
			for _, field := range []string{"path", "content"} {
				if !slices.Contains(files.Required, field) {
					t.Errorf("%s files items do not require %q (required = %v)", tc.id, field, files.Required)
				}
			}
		})
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
		// #2002: the runtime enforces output_schema_json, so a catalog that
		// declares one that cannot be parsed must fail at load, not leave the
		// skill silently unenforced.
		"malformed output_schema_json": `
skills:
  - id: x
    recipe_id: agent-runtime
    system_prompt: hi
    allowed_scopes: [containers:read]
    agent_card:
      id: x
      output_schema_json: '{not json'
`,
		"non-object output_schema_json": `
skills:
  - id: x
    recipe_id: agent-runtime
    system_prompt: hi
    allowed_scopes: [containers:read]
    agent_card:
      id: x
      output_schema_json: '["files"]'
`,
		// #2222: an unrecognized engine name must fail at catalog load, not
		// reach RunAgentSkill, where it would resolve as UNSPECIFIED and
		// silently run on the daemon's default engine instead.
		"unknown engine": `
skills:
  - id: x
    recipe_id: agent-runtime
    system_prompt: hi
    allowed_scopes: [containers:read]
    engine: cluade
`,
		"malformed input_schema_json": `
skills:
  - id: x
    recipe_id: agent-runtime
    system_prompt: hi
    allowed_scopes: [containers:read]
    agent_card:
      id: x
      input_schema_json: '{'
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
      output_schema_json: '{"type": "object", "required": ["ok"]}'
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
	// A well-formed schema passes validation and reaches the proto card
	// verbatim — it is what the daemon seeds as agent-card.json (#2002).
	if got := s.GetAgentCard().GetOutputSchemaJson(); got != `{"type": "object", "required": ["ok"]}` {
		t.Errorf("output_schema_json = %q, want it passed through verbatim", got)
	}
}

// TestEngineFieldRoundTrips covers #2222: engine is optional (an unset
// manifest keeps today's UNSPECIFIED/no-engine behaviour), and a named one
// parses case-insensitively to its typed proto value.
func TestEngineFieldRoundTrips(t *testing.T) {
	const withEngine = `
skills:
  - id: has-engine
    recipe_id: agent-runtime
    system_prompt: hi
    allowed_scopes: [containers:read]
    engine: Codex
  - id: no-engine
    recipe_id: agent-runtime
    system_prompt: hi
    allowed_scopes: [containers:read]
`
	m := New()
	if err := m.LoadFromBytes([]byte(withEngine)); err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	named, err := m.Get("has-engine")
	if err != nil {
		t.Fatalf("get has-engine: %v", err)
	}
	if named.GetEngine() != pb.AgentEngine_AGENT_ENGINE_CODEX {
		t.Errorf("has-engine: Engine = %v, want AGENT_ENGINE_CODEX", named.GetEngine())
	}
	unnamed, err := m.Get("no-engine")
	if err != nil {
		t.Fatalf("get no-engine: %v", err)
	}
	if unnamed.GetEngine() != pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED {
		t.Errorf("no-engine: Engine = %v, want AGENT_ENGINE_UNSPECIFIED (unset manifest)", unnamed.GetEngine())
	}
}
