package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// `code install` installs the pinned SDLC role skills for the Claude engine
// (#2065), the same as the coding-agent recipe does for a new box.

func withNoSDLCSkills(t *testing.T, v bool) {
	t.Helper()
	orig := codeNoSDLCSkills
	t.Cleanup(func() { codeNoSDLCSkills = orig })
	codeNoSDLCSkills = v
}

func TestCodeInstall_InstallsSDLCSkillsForClaude(t *testing.T) {
	withNoSDLCSkills(t, false)
	runs, _, err := runInstall(t, "alice", map[string]string{"release": "v9.9.9"})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	scripts := allScripts(runs)
	for _, want := range []string{"install-sdlc-skills.sh", "/v9.9.9/scripts/install-sdlc-skills.sh"} {
		if !strings.Contains(scripts, want) {
			t.Errorf("the SDLC skills step is missing %q:\n%s", want, scripts)
		}
	}
	if strings.Contains(scripts, "sudo") {
		t.Errorf("skills belong to the box user; no sudo:\n%s", scripts)
	}
}

func TestCodeInstall_NoSDLCSkillsFlagSkipsThem(t *testing.T) {
	withNoSDLCSkills(t, true)
	runs, _, err := runInstall(t, "alice", map[string]string{"release": "v9.9.9"})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if scripts := allScripts(runs); strings.Contains(scripts, "install-sdlc-skills") {
		t.Errorf("--no-sdlc-skills was set but the skills step ran:\n%s", scripts)
	}
	if f := codeInstallCmd.Flags().Lookup("no-sdlc-skills"); f == nil {
		t.Error("code install has no --no-sdlc-skills flag")
	}
}

// The skills are Claude Code skills (~/.claude/skills); another engine does
// not read them.
func TestCodeInstall_OtherEnginesDoNotGetClaudeSkills(t *testing.T) {
	withNoSDLCSkills(t, false)
	env, err := runInstallEngine(t, "alice", map[string]string{
		"engine": "pi", "credential": "gateway", "provider": "kafeido", "model": "kafeido-coder",
	}, okMint(), nil, nil)
	if err != nil {
		t.Fatalf("install: %v\nstderr: %s", err, env.stderr)
	}
	if scripts := env.allScripts(); strings.Contains(scripts, "install-sdlc-skills") {
		t.Errorf("a non-Claude engine got the Claude skills step:\n%s", scripts)
	}
}

// runSDLCSkillsScript executes the generated script against a fake curl that
// answers with a chosen HTTP status, and reports whether the installer ran.
func runSDLCSkillsScript(t *testing.T, status string) (out string, ok bool, ran bool) {
	t.Helper()
	for _, tool := range []string{"bash", "mktemp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "installer-ran")
	fakeCurl := "#!/bin/sh\n" +
		"out=''\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=\"$2\"; shift;; esac; shift; done\n" +
		"[ -n \"$out\" ] && printf '#!/bin/sh\\ntouch '\"'\"'" + marker + "'\"'\"'\\n' > \"$out\"\n" +
		"printf '%s' '" + status + "'\n"
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(fakeCurl), 0o700); err != nil { //nolint:gosec // test-only stand-in
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", sdlcSkillsInstallScript("v9.9.9")) //nolint:gosec // generated script under test
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "HOME="+dir)
	b, err := cmd.CombinedOutput()
	_, statErr := os.Stat(marker)
	return string(b), err == nil, statErr == nil
}

func TestSDLCSkillsInstallScript_OnlyA404SkipsAndOnlyA200Runs(t *testing.T) {
	if out, ok, ran := runSDLCSkillsScript(t, "200"); !ok || !ran {
		t.Errorf("200: ok=%v installer ran=%v, want both true\n%s", ok, ran, out)
	}
	out, ok, ran := runSDLCSkillsScript(t, "404")
	if !ok || ran {
		t.Errorf("404 (release predates the skills asset): ok=%v ran=%v, want ok and not run\n%s", ok, ran, out)
	}
	if !strings.Contains(out, "has no SDLC skills installer") {
		t.Errorf("404 skipped silently; output %q", out)
	}
	if out, ok, ran := runSDLCSkillsScript(t, "503"); ok || ran {
		t.Errorf("503: ok=%v ran=%v, want a failure that runs nothing\n%s", ok, ran, out)
	}
}
