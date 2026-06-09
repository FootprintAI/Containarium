package server

import (
	"strings"
	"testing"
)

func TestBuildAgentSeedScript(t *testing.T) {
	script := buildAgentSeedScript("be helpful", "tok-123", `{"q":"hi"}`)

	for _, want := range []string{
		"set -euo pipefail",
		"umask 077",
		"mkdir -p " + agentSeedDir,
		agentSeedDir + "/system_prompt.txt",
		agentSeedDir + "/token",
		agentSeedDir + "/input.json",
		"chmod 600 " + agentSeedDir + "/token",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("seed script missing %q\n---\n%s", want, script)
		}
	}
}

func TestBuildAgentSeedScriptDefaultsInput(t *testing.T) {
	script := buildAgentSeedScript("p", "t", "")
	if !strings.Contains(script, "'{}'") {
		t.Errorf("empty input should default to {}, got:\n%s", script)
	}
}

func TestBuildAgentSeedScriptEscapesSingleQuotes(t *testing.T) {
	// A system prompt containing a single quote must be escaped so it can't
	// break out of the shell-quoted printf argument.
	script := buildAgentSeedScript("don't panic", "t", "{}")
	if strings.Contains(script, "don't") && !strings.Contains(script, `don'\''t`) {
		t.Errorf("single quote not escaped in seed script:\n%s", script)
	}
}
