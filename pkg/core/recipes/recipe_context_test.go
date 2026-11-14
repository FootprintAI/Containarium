package recipes

import (
	"strings"
	"testing"
)

// contextYAML is a minimal recipe with a box_user parameter (the context
// directory lives in that user's home) and the given id and context block.
func contextYAML(id, context string) string {
	return "recipes:\n" +
		"  - id: " + id + "\n" +
		"    image: x\n" +
		"    parameters:\n" +
		"      - name: box_user\n" +
		"        label: Box user\n" +
		"        type: string\n" +
		"        default: ubuntu\n" +
		context
}

// TestLoadContext_DeclaredFilesReachTheProto: a declared context loads and
// maps its file names onto pb.RecipeContext (#3726).
func TestLoadContext_DeclaredFilesReachTheProto(t *testing.T) {
	m := New()
	if err := m.LoadFromBytes([]byte(contextYAML("docs-app", "    context:\n      files: [current.json, outline.json]\n"))); err != nil {
		t.Fatalf("load: %v", err)
	}
	r, err := m.Get("docs-app")
	if err != nil {
		t.Fatal(err)
	}
	got := r.GetContext().GetFiles()
	if len(got) != 2 || got[0] != "current.json" || got[1] != "outline.json" {
		t.Fatalf("context files = %v, want [current.json outline.json]", got)
	}
}

// TestLoadContext_AbsentMeansNoContext: a recipe that declares nothing has no
// context, so deploy creates no directory and no env var (opt-in).
func TestLoadContext_AbsentMeansNoContext(t *testing.T) {
	m := New()
	if err := m.LoadFromBytes([]byte(contextYAML("plain-app", ""))); err != nil {
		t.Fatalf("load: %v", err)
	}
	r, _ := m.Get("plain-app")
	if r.GetContext() != nil {
		t.Fatalf("context = %v, want nil for a recipe that declares none", r.GetContext())
	}
}

// TestLoadContext_RefusesUnsafeDeclarations: every name that becomes a path
// component, and every declaration that cannot work, is refused at load time
// and the error names the recipe.
func TestLoadContext_RefusesUnsafeDeclarations(t *testing.T) {
	cases := map[string]struct{ id, context, want string }{
		"path separator":   {"docs-app", "    context:\n      files: [sub/current.json]\n", "plain file name"},
		"parent reference": {"docs-app", "    context:\n      files: [..]\n", "plain file name"},
		"leading dot":      {"docs-app", "    context:\n      files: [.hidden.json]\n", "plain file name"},
		"duplicate":        {"docs-app", "    context:\n      files: [a.json, a.json]\n", "twice"},
		"no files":         {"docs-app", "    context:\n      files: []\n", "must list"},
		"upper-case id":    {"Docs_App", "    context:\n      files: [a.json]\n", "lower-case"},
		"no box_user":      {"docs-app", "", "box_user"},
	}
	for name, tc := range cases {
		yaml := contextYAML(tc.id, tc.context)
		if name == "no box_user" {
			yaml = "recipes:\n  - id: docs-app\n    image: x\n    context:\n      files: [a.json]\n"
		}
		err := New().LoadFromBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: load = %v, want an error containing %q", name, err, tc.want)
		}
	}
}
