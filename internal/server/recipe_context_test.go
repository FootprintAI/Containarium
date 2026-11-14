package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeContextTools writes stand-ins for getent (answers "passwd <user>" from
// FAKE_USER/FAKE_HOME) and install (creates the directory it is given). The
// prelude's install -d -o/-g need root, so the tests run it without them.
func fakeContextTools(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	getent := `#!/bin/sh
[ "$2" = "$FAKE_USER" ] || exit 2
echo "$FAKE_USER:x:1000:1000::$FAKE_HOME:/bin/sh"
`
	install := `#!/bin/sh
for last; do :; done
mkdir -p "$last"
`
	for name, body := range map[string]string{"getent": getent, "install": install} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return bin
}

// runContextPrelude runs the prelude the way post_start does (set -euo
// pipefail first) against a fake home and returns the combined output and
// exit error.
func runContextPrelude(t *testing.T, recipe *pb.Recipe, home, profile string) (string, error) {
	t.Helper()
	script := "set -euo pipefail\n" + contextSetupScript(recipe, map[string]string{"box_user": "dev"}, profile)
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = []string{
		"PATH=" + fakeContextTools(t) + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_USER=dev",
		"FAKE_HOME=" + home,
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func docsRecipe() *pb.Recipe {
	return &pb.Recipe{Id: "docs-app", Context: &pb.RecipeContext{Files: []string{"current.json"}}}
}

// TestContextPrelude_CreatesDirectoryAndExportsVariable: a declared context
// gets an empty directory under the box user's home, the env var names it,
// and the profile file carries the same export for later login shells.
func TestContextPrelude_CreatesDirectoryAndExportsVariable(t *testing.T) {
	home := t.TempDir()
	profile := filepath.Join(t.TempDir(), "containarium-context.sh")
	if out, err := runContextPrelude(t, docsRecipe(), home, profile); err != nil {
		t.Fatalf("prelude failed: %v\n%s", err, out)
	}
	dir := filepath.Join(home, ".containarium", "context", "docs-app")
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("context directory %s not created: %v", dir, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("context directory not empty before the app writes: %d entries", len(entries))
	}
	body, err := os.ReadFile(profile)
	if err != nil {
		t.Fatalf("profile file not written: %v", err)
	}
	if want := "export CONTAINARIUM_CONTEXT_DIR='" + dir + "'"; strings.TrimSpace(string(body)) != want {
		t.Errorf("profile file = %q, want %q", body, want)
	}
}

// TestContextPrelude_RefusesPlantedSymlink: a symlink where the context
// directory belongs stops the prelude before anything is written through it
// (the same class as #3652: root must not follow a user-planted link).
func TestContextPrelude_RefusesPlantedSymlink(t *testing.T) {
	home := t.TempDir()
	victim := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".containarium"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(home, ".containarium", "context")); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(t.TempDir(), "containarium-context.sh")
	out, err := runContextPrelude(t, docsRecipe(), home, profile)
	if err == nil || !strings.Contains(out, "refusing symlink") {
		t.Fatalf("prelude followed a planted symlink: err=%v out=%s", err, out)
	}
	if entries, _ := os.ReadDir(victim); len(entries) != 0 {
		t.Errorf("symlink target was written: %d entries", len(entries))
	}
	if _, err := os.Stat(profile); err == nil {
		t.Error("profile file written after the refusal")
	}
}

// TestContextPrelude_UnknownBoxUserFails: without a home for the box user the
// prelude fails rather than guessing a path.
func TestContextPrelude_UnknownBoxUserFails(t *testing.T) {
	home := t.TempDir()
	script := "set -euo pipefail\n" + contextSetupScript(docsRecipe(), map[string]string{"box_user": "nobody-here"}, filepath.Join(t.TempDir(), "p.sh"))
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = []string{
		"PATH=" + fakeContextTools(t) + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_USER=dev",
		"FAKE_HOME=" + home,
	}
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("prelude succeeded for an unknown box user: %s", out)
	}
	if _, err := os.Stat(filepath.Join(home, ".containarium")); err == nil {
		t.Error("a directory was created for an unknown box user")
	}
}

// TestBuildPostStartScript_NoContextIsUnchanged: a recipe that declares no
// context gets no prelude, no directory and no env var in post_start.
func TestBuildPostStartScript_NoContextIsUnchanged(t *testing.T) {
	plain := &pb.Recipe{Id: "plain-app"}
	if got := contextSetupScript(plain, map[string]string{"box_user": "dev"}, "/x"); got != "" {
		t.Errorf("prelude for a recipe with no context = %q, want empty", got)
	}
	if s := buildPostStartScript(plain, map[string]string{}, ""); strings.Contains(s, "CONTAINARIUM_CONTEXT_DIR") {
		t.Errorf("post_start mentions the context variable for a recipe with no context:\n%s", s)
	}
	if s := buildPostStartScript(docsRecipe(), map[string]string{"box_user": "dev"}, ""); !strings.Contains(s, "CONTAINARIUM_CONTEXT_DIR") {
		t.Errorf("post_start for a recipe with a context does not export the variable:\n%s", s)
	}
}
