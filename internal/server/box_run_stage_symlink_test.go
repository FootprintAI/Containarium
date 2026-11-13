package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The root-run staging script must not follow a symlink planted in the run
// user's home: a write, a delete or a chown through it would reach a file the
// run user chose (#3703). The test runs the real generated script with a
// no-op chown (the test is not root and has no run user).
func runStage(t *testing.T, ownerHome, runHome string) (string, error) {
	t.Helper()
	script, err := boxRunStageScript(ownerHome, runHome)
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "chown"), []byte("#!/bin/bash\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func stageHomes(t *testing.T) (owner, run, outside string) {
	t.Helper()
	owner = t.TempDir()
	run = t.TempDir()
	outside = t.TempDir()
	if err := os.MkdirAll(filepath.Join(owner, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(owner, ".claude", "settings.json"), []byte(`{"home":"`+owner+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return owner, run, outside
}

func TestStageRefusesASymlinkedClaudeDir(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	owner, run, outside := stageHomes(t)
	if err := os.Symlink(outside, filepath.Join(run, ".claude")); err != nil {
		t.Fatal(err)
	}
	out, err := runStage(t, owner, run)
	if err == nil {
		t.Fatalf("staging followed a symlinked .claude dir; output: %s", out)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("a file was written through the symlinked dir: %d entries", len(entries))
	}
}

func TestStageRefusesASymlinkedConfigFile(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	owner, run, outside := stageHomes(t)
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(run, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(run, ".claude", "settings.json")); err != nil {
		t.Fatal(err)
	}
	out, err := runStage(t, owner, run)
	if err == nil {
		t.Fatalf("staging wrote through a symlinked settings.json; output: %s", out)
	}
	got, _ := os.ReadFile(victim)
	if strings.TrimSpace(string(got)) != "keep" {
		t.Errorf("symlink target was modified: %q", got)
	}
}

func TestStageStillStagesACleanHome(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	owner, run, _ := stageHomes(t)
	if out, err := runStage(t, owner, run); err != nil {
		t.Fatalf("clean stage failed: %v\n%s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(run, ".claude", "settings.json"))
	if err != nil {
		t.Fatalf("settings.json not staged: %v", err)
	}
	if !strings.Contains(string(got), run) || strings.Contains(string(got), owner) {
		t.Errorf("settings.json home not rewritten: %q", got)
	}
}
