package container

import "strings"

import "testing"

func TestGitWorkspacePath(t *testing.T) {
	if got := gitWorkspacePath(""); got != "/workspace" {
		t.Errorf("empty → %q, want /workspace", got)
	}
	if got := gitWorkspacePath("  "); got != "/workspace" {
		t.Errorf("blank → %q, want /workspace", got)
	}
	if got := gitWorkspacePath("/srv/app"); got != "/srv/app" {
		t.Errorf("explicit → %q, want /srv/app", got)
	}
}

func TestBuildGitFetchScript_PublicRepoWithRef(t *testing.T) {
	s := buildGitFetchScript("https://github.com/org/repo", "abc123", "", "")

	wantContains := []string{
		"git init -q",
		"fetch --depth 1 -q 'https://github.com/org/repo' 'abc123'",
		"git checkout -q FETCH_HEAD",
		"mkdir -p '/workspace'",
	}
	for _, w := range wantContains {
		if !strings.Contains(s, w) {
			t.Errorf("script missing %q\n---\n%s", w, s)
		}
	}
	if strings.Contains(s, "http.extraHeader") {
		t.Errorf("public repo must not inject an auth header:\n%s", s)
	}
}

func TestBuildGitFetchScript_PrivateRepoInjectsEphemeralHeader(t *testing.T) {
	token := "ghs_SECRETTOKEN"
	s := buildGitFetchScript("https://github.com/org/repo", "deadbeef", token, "/ws")

	// Token must be present only as an ephemeral http.extraHeader on
	// the fetch — never written to .git/config (no `git config` line
	// carrying it), so it doesn't persist in the box.
	if !strings.Contains(s, "-c http.extraHeader='AUTHORIZATION: bearer "+token+"'") {
		t.Errorf("expected ephemeral extraHeader with token, got:\n%s", s)
	}
	if strings.Contains(s, "git config") {
		t.Errorf("token/header must not be written via `git config` (would persist):\n%s", s)
	}
	if !strings.Contains(s, "mkdir -p '/ws'") {
		t.Errorf("custom workspace not honored:\n%s", s)
	}
}

func TestBuildGitFetchScript_EmptyRefFetchesDefault(t *testing.T) {
	s := buildGitFetchScript("https://github.com/org/repo", "", "", "")
	// No trailing ref arg after the URL when ref is empty.
	if !strings.Contains(s, "fetch --depth 1 -q 'https://github.com/org/repo'\n") {
		t.Errorf("empty ref should fetch default branch (no ref arg):\n%s", s)
	}
}

func TestBuildGitFetchScript_ShellInjectionIsQuoted(t *testing.T) {
	// A malicious ref must not break out of the command.
	s := buildGitFetchScript("https://github.com/org/repo", "x'; rm -rf /; '", "", "")
	if strings.Contains(s, "; rm -rf /; ") && !strings.Contains(s, `'\''`) {
		t.Errorf("ref not shell-escaped — injection risk:\n%s", s)
	}
}
