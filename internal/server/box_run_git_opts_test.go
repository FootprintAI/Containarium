package server

import (
	"regexp"
	"strings"
	"testing"
)

// bashRuleMatches models how the agent CLI matches a `Bash(<pattern>)` rule
// against one simple command: `*` matches any run of characters (spaces
// included) and the whole command must match.
func bashRuleMatches(rule, cmd string) bool {
	if !strings.HasPrefix(rule, "Bash(") || !strings.HasSuffix(rule, ")") {
		return false
	}
	pat := strings.TrimSuffix(strings.TrimPrefix(rule, "Bash("), ")")
	re := "^" + strings.ReplaceAll(regexp.QuoteMeta(pat), `\*`, ".*") + "$"
	return regexp.MustCompile(re).MatchString(cmd)
}

// bashDecision applies deny-before-allow, as the CLI does.
func bashDecision(p boxRunPolicy, cmd string) (allowed bool) {
	for _, r := range p.Denied {
		if bashRuleMatches(r, cmd) {
			return false
		}
	}
	for _, r := range p.Allowed {
		if bashRuleMatches(r, cmd) {
			return true
		}
	}
	return false
}

// #3385: the read-only option-led forms of the already-allowed git
// subcommands run unattended; the dangerous ones stay refused.
func TestBoxRunPolicy_GitOptionLedForms(t *testing.T) {
	for _, level := range []string{"none", "build_tools", "full_sudo"} {
		p, err := boxRunPolicyFor(level)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			cmd  string
			want bool
		}{
			// unchanged baseline
			{"git status", true},
			{"git rev-parse HEAD", true},
			{"git push", false},
			{"git push origin main", false},
			{"git remote add x y", false},
			// newly allowed
			{"git -C /home/u/work/repo rev-parse HEAD", true},
			{"git -C /home/u/work/repo status", true},
			{"git -C /home/u/work/repo log --oneline -5", true},
			{"git -C /home/u/work/repo diff HEAD~1", true},
			{"git -C /home/u/work/repo commit -m msg", true},
			{"git --git-dir=/r/.git rev-parse HEAD", true},
			{"git --work-tree=/r status", true},
			{"git --git-dir=/r/.git --work-tree=/r status", true},
			{"git -C /r --git-dir=/r/.git ls-files", true},
			// still refused
			{"git -C /r push", false},
			{"git -C /r push origin main", false},
			{"git -C /r push status", false},
			{"git -C /r remote add x y", false},
			{"git -C /r remote -v", false},
			{"git -C /r config user.name x", false},
			{"git -C /r -c core.sshCommand=evil fetch", false},
			{"git -c core.sshCommand=evil fetch", false},
			{"git -C /r -c core.pager=evil log", false},
			{"git --git-dir=/r/.git -c core.x=y status", false},
			{"git -C /r --upload-pack=evil fetch origin", false},
			{"git -C /r --exec-path=/tmp/x status", false},
			{"git --exec-path=/tmp/x status", false},
			{"git -C /r --config-env=a=B status", false},
			{"git -C /r fetch --upload-pack=evil origin", false},
			{"git -C /r clone --upload-pack=evil u d", false},
			{"git -C /r rm -r .", false},
			{"git -C /r reset --hard", false},
		} {
			if got := bashDecision(p, tc.cmd); got != tc.want {
				t.Errorf("%s: %q allowed = %v, want %v", level, tc.cmd, got, tc.want)
			}
		}
	}
}

// The deny rules are emitted as their own flag, before the variadic
// --allowedTools.
func TestBoxRunPolicy_DeniedRulesAreEmitted(t *testing.T) {
	p, err := boxRunPolicyFor("none")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Denied) == 0 {
		t.Fatal("no deny rules")
	}
	f := p.commandFlags()
	d, a := strings.Index(f, "--disallowedTools"), strings.Index(f, "--allowedTools")
	if d < 0 || a < 0 || d > a {
		t.Fatalf("--disallowedTools must be present and precede --allowedTools:\n%s", f)
	}
}
