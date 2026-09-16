package server

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuildWorkspaceSeedScript pins the daemon side of the workspace contract
// (design doc §5, coding-skill-on-a-repo, cloud repo): <seed>/workspace.json
// carries exactly the fields a runtime needs to bind its file tools to the
// checkout without re-deriving the path from the run id — path, and the repo
// coordinates the response already reports (git_source/git_ref/git_commit).
func TestBuildWorkspaceSeedScript(t *testing.T) {
	seedDir := seedDirFor("run-git-1")
	script := buildWorkspaceSeedScript(seedDir, workspaceSeed{
		Path:      workspaceDirFor("run-git-1"),
		GitSource: "https://github.com/octocat/Spoon-Knife",
		GitRef:    "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9",
		GitCommit: "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9",
	})

	if !strings.Contains(script, "mkdir -p "+seedDir) {
		t.Errorf("script does not ensure the seed dir exists:\n%s", script)
	}
	if !strings.Contains(script, seedDir+"/workspace.json") {
		t.Errorf("script does not write workspace.json into the seed dir:\n%s", script)
	}

	// The JSON payload itself, single-quoted for printf, must decode back to
	// exactly what was passed in — a stale/hand-rolled script would drift
	// silently on a field rename, this catches it.
	payload := extractSingleQuotedPrintfArg(t, script)
	var got workspaceSeed
	if err := json.Unmarshal([]byte(payload), &got); err != nil {
		t.Fatalf("workspace.json payload is not valid JSON: %v\npayload: %s", err, payload)
	}
	want := workspaceSeed{
		Path:      "/workspace/runs/run-git-1",
		GitSource: "https://github.com/octocat/Spoon-Knife",
		GitRef:    "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9",
		GitCommit: "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9",
	}
	if got != want {
		t.Errorf("workspace.json decoded to %+v, want %+v", got, want)
	}
}

// TestBuildWorkspaceSeedScriptEscapesSingleQuotes proves a git_source/ref
// carrying a single quote can't break out of the printf argument's shell
// quoting — same defect class buildAgentSeedScript already guards
// (TestBuildAgentSeedScriptEscapesSingleQuotes), reapplied here because this
// script's caller-controlled fields (git_source, git_ref) are a repo URL and a
// ref string a caller chose, not a system prompt this repo authored.
func TestBuildWorkspaceSeedScriptEscapesSingleQuotes(t *testing.T) {
	script := buildWorkspaceSeedScript(seedDirFor("run-1"), workspaceSeed{
		Path:      "/workspace/runs/run-1",
		GitSource: "https://github.com/org/it's-a-repo",
		GitRef:    "main",
		GitCommit: "deadbeef",
	})
	payload := extractSingleQuotedPrintfArg(t, script)
	var got workspaceSeed
	if err := json.Unmarshal([]byte(payload), &got); err != nil {
		t.Fatalf("escaped payload failed to decode as JSON: %v\nscript:\n%s", err, script)
	}
	if got.GitSource != "https://github.com/org/it's-a-repo" {
		t.Errorf("GitSource round-tripped as %q, want the original unescaped value", got.GitSource)
	}
}

// extractSingleQuotedPrintfArg pulls the single-quoted argument out of the
// script's `printf '%s' '<payload>' > .../workspace.json` line and undoes
// shell single-quote escaping, so the test can assert on the JSON it
// actually decodes to rather than string-matching the shell-quoted form.
func extractSingleQuotedPrintfArg(t *testing.T, script string) string {
	t.Helper()
	const marker = "printf '%s' '"
	i := strings.Index(script, marker)
	if i < 0 {
		t.Fatalf("script does not contain a printf '%%s' '...' line:\n%s", script)
	}
	rest := script[i+len(marker):]
	end := strings.Index(rest, "' >")
	if end < 0 {
		t.Fatalf("could not find the closing quote of the printf argument:\n%s", script)
	}
	// Undo shellSingleQuote's escaping: `'\''` -> `'`.
	return strings.ReplaceAll(rest[:end], `'\''`, "'")
}
