package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/sdlcskills"
)

// `code install` installs the pinned SDLC role skills for the Claude engine
// (#2065), the same as the coding-agent recipe does for a new box.

func withNoSDLCSkills(t *testing.T, v bool) {
	t.Helper()
	orig, origSets := codeNoSDLCSkills, codeSkillSets
	t.Cleanup(func() { codeNoSDLCSkills, codeSkillSets = orig, origSets })
	codeNoSDLCSkills, codeSkillSets = v, ""
}

func withSkillSets(t *testing.T, sets string, noSDLC bool) {
	t.Helper()
	withNoSDLCSkills(t, noSDLC)
	codeSkillSets = sets
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

// --no-sdlc-skills is a deprecated alias for --skill-sets none (#3048): the
// installer still runs, with SKILL_SETS=none, so skills it owned are removed.
func TestCodeInstall_NoSDLCSkillsFlagIsAnAliasForNone(t *testing.T) {
	withNoSDLCSkills(t, true)
	runs, _, err := runInstall(t, "alice", map[string]string{"release": "v9.9.9"})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if scripts := allScripts(runs); !strings.Contains(scripts, `SKILL_SETS="none"`) {
		t.Errorf("--no-sdlc-skills did not map to SKILL_SETS=none:\n%s", scripts)
	}
	f := codeInstallCmd.Flags().Lookup("no-sdlc-skills")
	if f == nil {
		t.Fatal("code install has no --no-sdlc-skills flag")
	}
	if !strings.Contains(f.Deprecated, "--skill-sets none") {
		t.Errorf("--no-sdlc-skills deprecation note = %q, want it to name --skill-sets none", f.Deprecated)
	}
}

func TestCodeInstall_SkillSetsFlagSelectsSets(t *testing.T) {
	for in, want := range map[string]string{"": `SKILL_SETS="all"`, "qa": `SKILL_SETS="qa"`, "sdlc, qa": `SKILL_SETS="sdlc,qa"`, "none": `SKILL_SETS="none"`} {
		withSkillSets(t, in, false)
		runs, _, err := runInstall(t, "alice", map[string]string{"release": "v9.9.9"})
		if err != nil {
			t.Fatalf("--skill-sets %q: %v", in, err)
		}
		if scripts := allScripts(runs); !strings.Contains(scripts, want) {
			t.Errorf("--skill-sets %q: script lacks %s:\n%s", in, want, scripts)
		}
	}
	if f := codeInstallCmd.Flags().Lookup("skill-sets"); f == nil {
		t.Error("code install has no --skill-sets flag")
	}
}

func TestCodeInstall_SkillSetsAreValidatedBeforeAnythingRuns(t *testing.T) {
	for _, tc := range []struct {
		sets   string
		noSDLC bool
	}{{"qa;touch x", false}, {"$(id)", false}, {"QA", false}, {"qa,none", false}, {"qa", true}} {
		withSkillSets(t, tc.sets, tc.noSDLC)
		runs, _, err := runInstall(t, "alice", map[string]string{"release": "v9.9.9"})
		if err == nil {
			t.Errorf("--skill-sets %q (no-sdlc-skills=%v) accepted", tc.sets, tc.noSDLC)
		}
		if len(runs) != 0 {
			t.Errorf("--skill-sets %q: %d scripts ran before the flag was rejected", tc.sets, len(runs))
		}
	}
	// --no-sdlc-skills together with --skill-sets none is consistent, not a conflict.
	withSkillSets(t, "none", true)
	if _, _, err := runInstall(t, "alice", map[string]string{"release": "v9.9.9"}); err != nil {
		t.Errorf("--no-sdlc-skills with --skill-sets none: %v", err)
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
	return runSDLCSkillsScriptSets(t, status, "all", "")
}

// runSDLCSkillsScriptSets is the same with a chosen selection and installer body.
func runSDLCSkillsScriptSets(t *testing.T, status, sets, installerBody string) (out string, ok bool, ran bool) {
	t.Helper()
	for _, tool := range []string{"bash", "mktemp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	parsed, err := sdlcskills.ParseSkillSets(sets)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "installer-ran")
	fakeCurl := "#!/bin/sh\n" +
		"out=''\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=\"$2\"; shift;; esac; shift; done\n" +
		"[ -n \"$out\" ] && printf '#!/bin/sh\\n" + installerBody + "touch '\"'\"'" + marker + "'\"'\"'\\n' > \"$out\"\n" +
		"printf '%s' '" + status + "'\n"
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(fakeCurl), 0o700); err != nil { //nolint:gosec // test-only stand-in
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", sdlcSkillsInstallScript("v9.9.9", parsed)) //nolint:gosec // generated script under test
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

// An installer that predates skill sets would ignore the selection (#3048).
// Detection is a dedicated marker line, not a mention of SKILL_SETS.
func TestSDLCSkillsInstallScript_OldInstallerHandling(t *testing.T) {
	const marker = "# skill-sets: v1\n"
	cases := []struct {
		name, status, sets, body string
		wantOK, wantRan          bool
		wantMsg                  string
	}{
		{"old installer, all: runs as before", "200", "all", "", true, true, ""},
		{"old installer, none: skips (nothing to prune)", "200", "none", "", true, false, "predates skill sets"},
		{"old installer, subset: refused", "200", "qa", "", false, false, "predates skill sets"},
		{"a mere mention of SKILL_SETS is not the marker", "200", "qa", "# honours SKILL_SETS\n", false, false, "predates skill sets"},
		{"marked installer, subset: runs", "200", "qa", marker, true, true, ""},
		{"marked installer, none: runs (prunes)", "200", "none", marker, true, true, ""},
		{"no installer at all, all: skipped", "404", "all", "", true, false, "has no SDLC skills installer"},
		{"no installer at all, none: skipped", "404", "none", "", true, false, "has no SDLC skills installer"},
		{"no installer at all, subset: refused", "404", "qa", "", false, false, "has no SDLC skills installer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, ok, ran := runSDLCSkillsScriptSets(t, tc.status, tc.sets, tc.body)
			if ok != tc.wantOK || ran != tc.wantRan {
				t.Errorf("ok=%v ran=%v, want ok=%v ran=%v\n%s", ok, ran, tc.wantOK, tc.wantRan, out)
			}
			if tc.wantMsg != "" && !strings.Contains(out, tc.wantMsg) {
				t.Errorf("output %q does not mention %q", out, tc.wantMsg)
			}
		})
	}
}

// The installer shipped in this repo carries the marker the wrappers look for.
func TestInstallSDLCSkills_CarriesTheSkillSetsMarker(t *testing.T) {
	b, err := os.ReadFile(installSDLCSkillsScript) //nolint:gosec // fixed repo path
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains("\n"+string(b), "\n# skill-sets: v1\n") {
		t.Error("install-sdlc-skills.sh lacks the '# skill-sets: v1' marker line")
	}
}
