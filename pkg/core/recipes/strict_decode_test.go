package recipes

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestLoadRejectsUnknownRecipeFields verifies that misspelt control keys are
// rejected with the recipe ID and key, even when the ID follows the typo.
func TestLoadRejectsUnknownRecipeFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		body string
	}{
		{"guardrail gate", "guardrail_gat", "    guardrail_gat:\n      dataset_path: /data\n"},
		{"model gateway", "model_gateway_provder", "    model_gateway_provder: openai\n"},
		{"resources", "resouces", "    resouces:\n      cpu: '2'\n"},
		{"cpu", "cpus", "    resources:\n      cpus: '2'\n"},
		{"memory", "memroy", "    resources:\n      memroy: 4GiB\n"},
		{"disk", "diks", "    resources:\n      diks: 20GiB\n"},
		{"ports", "prts", "    prts:\n      - container_port: 8080\n"},
		{"protocol", "protocl", "    ports:\n      - container_port: 8080\n        protocl: tcp\n"},
		{"external port", "external_prt", "    ports:\n      - container_port: 8080\n        external_prt: 18080\n"},
		{"parameters", "paramters", "    paramters:\n      - name: token\n        required: true\n"},
		{"required parameter", "requried", "    parameters:\n      - name: token\n        requried: true\n"},
		{"gpu", "requires_gup", "    requires_gup: true\n"},
		{"volume", "paht", "    volumes:\n      - name: data\n        paht: /data\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The offending key precedes its ID, between two valid recipes.
			catalog := "recipes:\n  - id: before\n    image: x\n  - image: x\n" +
				tc.body + "    id: typo-target\n  - id: after\n    image: x\n"
			err := New().LoadFromBytes([]byte(catalog))
			if err == nil {
				t.Fatalf("load accepted unknown field %q", tc.key)
			}
			if !strings.Contains(err.Error(), `recipe "typo-target"`) || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("load = %v, want an error naming recipe typo-target and %q", err, tc.key)
			}
		})
	}
}

// TestLoadUnknownFieldsNameEachRecipe checks that errors from multiple recipes
// retain their own recipe IDs and original YAML line numbers.
func TestLoadUnknownFieldsNameEachRecipe(t *testing.T) {
	err := New().LoadFromBytes([]byte(`recipes:
  - id: first
    image: x
    requires_gup: true
  - id: second
    image: x
    ports:
      - container_port: 8080
        protocl: tcp
`))
	if err == nil {
		t.Fatal("load accepted unknown fields in two recipes")
	}
	for _, want := range []string{
		`recipe "first": line 4: field requires_gup`,
		`recipe "second": line 9: field protocl`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("load = %v, want %q", err, want)
		}
	}
}

// TestLoadUnknownFieldsInFlowRecipes verifies that recipes sharing a source
// line receive distinct error attribution without implicating valid recipes.
func TestLoadUnknownFieldsInFlowRecipes(t *testing.T) {
	err := New().LoadFromBytes([]byte(`recipes: [{id: valid, image: x}, {id: first, image: x, requires_gup: true}, {id: second, image: x, requires_gup: true}]`))
	if err == nil {
		t.Fatal("load accepted unknown fields in flow recipes")
	}
	for _, id := range []string{"first", "second"} {
		if want := `recipe "` + id + `": line 1: field requires_gup`; !strings.Contains(err.Error(), want) {
			t.Errorf("load = %v, want %q", err, want)
		}
	}
	if strings.Contains(err.Error(), `recipe "valid"`) {
		t.Fatalf("unknown field incorrectly attributed to a valid recipe: %v", err)
	}
}

// TestLoadRejectsUnknownCatalogField checks that unknown document-level keys
// are rejected without attributing the catalog error to a valid recipe.
func TestLoadRejectsUnknownCatalogField(t *testing.T) {
	err := New().LoadFromBytes([]byte("recipes:\n  - id: valid\n    image: x\nrecpies: []\n"))
	if err == nil || !strings.Contains(err.Error(), "recpies") {
		t.Fatalf("load = %v, want an unknown recpies field error", err)
	}
	if strings.Contains(err.Error(), `recipe "valid"`) {
		t.Fatalf("catalog error incorrectly attributed to a valid recipe: %v", err)
	}
}

// TestLoadUnknownFieldPreservesCatalog ensures that a failed reload leaves the
// previous catalog intact instead of publishing a partial replacement.
func TestLoadUnknownFieldPreservesCatalog(t *testing.T) {
	m := New()
	if err := m.LoadFromBytes([]byte("recipes:\n  - id: original\n    image: x\n")); err != nil {
		t.Fatal(err)
	}
	err := m.LoadFromBytes([]byte("recipes:\n  - id: replacement\n    image: x\n  - id: invalid\n    image: x\n    requires_gup: true\n"))
	if err == nil {
		t.Fatal("load accepted an unknown field")
	}
	if got := m.List(); len(got) != 1 || got[0].Id != "original" {
		t.Fatalf("failed load replaced catalog: %v", got)
	}
}

// TestEmbeddedCatalogLoadsEveryRecipe checks that strict decoding accepts every
// recipe declared in the embedded catalog and makes each ID retrievable.
func TestEmbeddedCatalogLoadsEveryRecipe(t *testing.T) {
	data, err := embeddedFS.ReadFile("recipes.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Recipes []struct {
			ID string `yaml:"id"`
		} `yaml:"recipes"`
	}
	if err := yaml.Unmarshal(data, &inventory); err != nil {
		t.Fatal(err)
	}
	if len(inventory.Recipes) == 0 {
		t.Fatal("embedded catalog is empty")
	}
	m := New()
	if err := m.LoadEmbedded(); err != nil {
		t.Fatal(err)
	}
	if got := len(m.List()); got != len(inventory.Recipes) {
		t.Fatalf("loaded %d recipes, want all %d", got, len(inventory.Recipes))
	}
	for _, recipe := range inventory.Recipes {
		if _, err := m.Get(recipe.ID); err != nil {
			t.Errorf("built-in recipe %q did not load: %v", recipe.ID, err)
		}
	}
}

// TestLoadStrictCatalogPreservesValidYAML verifies that strict field checking
// preserves shared YAML anchors and arbitrary environment variable names.
func TestLoadStrictCatalogPreservesValidYAML(t *testing.T) {
	m := New()
	if err := m.LoadFromBytes([]byte(`recipes:
  - id: first
    image: x
    resources: &limits
      cpu: '2'
      memory: 4GiB
    env:
      APP_SETTING: enabled
      protocl: arbitrary-env-key
  - id: second
    image: x
    resources: *limits
`)); err != nil {
		t.Fatal(err)
	}
	r, err := m.Get("second")
	if err != nil {
		t.Fatal(err)
	}
	if r.GetResources().GetCpu() != "2" || r.GetResources().GetMemory() != "4GiB" {
		t.Fatalf("YAML alias lost resource limits: %v", r.GetResources())
	}
	r, err = m.Get("first")
	if err != nil {
		t.Fatal(err)
	}
	if r.Env["APP_SETTING"] != "enabled" || r.Env["protocl"] != "arbitrary-env-key" {
		t.Fatalf("environment keys did not survive strict decoding: %v", r.Env)
	}
}

// TestLoadEmptyCatalog checks that the loader continues to accept the supported
// empty YAML documents and empty recipe lists.
func TestLoadEmptyCatalog(t *testing.T) {
	for _, catalog := range []string{"", "# empty catalog\n", "null", "{}", "recipes: []", "recipes:\n"} {
		m := New()
		if err := m.LoadFromBytes([]byte(catalog)); err != nil {
			t.Errorf("load %q: %v", catalog, err)
		}
		if len(m.List()) != 0 {
			t.Errorf("load %q produced recipes", catalog)
		}
	}
}
