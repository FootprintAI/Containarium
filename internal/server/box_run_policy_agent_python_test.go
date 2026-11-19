package server

import (
	"testing"

	"github.com/footprintai/containarium/internal/runhook"
)

// The Python dependency helper (#3788 slice 2) is a BUILD_TOOLS command with a
// fixed grammar: `agent-python setup|test|venv [DIR]`. Its `-- CMD` passthrough
// form stays refused at every level, and so does every other way of getting a
// `pip install` out of it. Decided by the same permission hook a run uses.
func TestBoxRunPolicy_AgentPythonGrammar(t *testing.T) {
	decide := func(level, cmd string) runhook.Decision {
		p, err := boxRunPolicyFor(level)
		if err != nil {
			t.Fatal(err)
		}
		return runhook.Decide(runhook.Config{LevelAllowed: p.Allowed, LevelDenied: p.Denied}, cmd)
	}
	allowed := []string{
		"agent-python setup", "agent-python setup .", "agent-python setup sub/dir",
		"agent-python test", "agent-python test .", "agent-python test sub",
		"agent-python venv", "agent-python venv .",
		"agent-python setup . && agent-python test .",
		"cd sub && agent-python setup",
		"agent-python test . | ls",
	}
	refused := []string{
		// The passthrough form: any command after `--`, with or without a DIR.
		"agent-python test -- pip install requests",
		"agent-python test . -- pip install requests",
		"agent-python test . -- python3 -c 'print(1)'",
		"agent-python test --",
		"agent-python test . --",
		"agent-python setup . -- pip install x",
		"agent-python venv -- ls",
		// The same form spelled so the raw text has no literal " -- " but the
		// shell sees a "--" word: quoted, escaped, split by a quote pair, or
		// separated by tabs.
		"agent-python test . '--' pip install x",
		`agent-python test . "--" pip install x`,
		`agent-python test . \-- pip install x`,
		"agent-python test . -''- pip install x",
		"agent-python test '--' pip",
		"agent-python test .\t--\tpip install x",
		"agent-python test . --\tpip install x",
		"agent-python test .\t--",
		"sudo agent-python test -- x",
		"sudo agent-python test . '--' pip install x",
		// Other subcommands, flags and bare helper.
		"agent-python", "agent-python help", "agent-python -h", "agent-python --help",
		"agent-python pip install requests", "agent-python setupx", "agent-python testx",
		"agent-python-evil setup", "/usr/local/bin/agent-python setup", "./agent-python setup",
		// Environment assignments in front change what pip reads; they are not
		// part of any rule.
		"PIP_INDEX_URL=https://example.invalid/simple agent-python setup",
		"PIP_NO_INDEX=1 agent-python setup .",
		"AGENT_PYTHON_VENV=/tmp/v agent-python setup",
		// Plain pip and python3 stay closed.
		"pip install requests", "pip3 install -r requirements.txt", "python3 -m pip install requests",
		"python3 -m venv .v", "python3 -c 'print(1)'", "python3 script.py",
		// One allowed segment never carries another that is not.
		"agent-python setup . && pip install x",
		"agent-python setup; python3 -m pip install x",
		"agent-python test . | python3",
		"agent-python setup . && agent-python test . -- pip install x",
		"agent-python setup $(pip install x)",
	}
	for _, cmd := range allowed {
		for _, level := range []string{"build_tools", "full_sudo"} {
			if d := decide(level, cmd); d.Verdict != runhook.VerdictDefer {
				t.Errorf("%s: Decide(%q) = %+v, want it left to the level's rules", level, cmd, d)
			}
		}
		if d := decide("none", cmd); d.Verdict != runhook.VerdictDeny {
			t.Errorf("none: Decide(%q) = %+v, want deny", cmd, d)
		}
	}
	for _, cmd := range refused {
		for _, level := range []string{"none", "build_tools", "full_sudo"} {
			if d := decide(level, cmd); d.Verdict != runhook.VerdictDeny {
				t.Errorf("%s: Decide(%q) = %+v, want deny", level, cmd, d)
			}
		}
	}
}

// The same grammar as the flags the run command carries: the allow rules are
// present from BUILD_TOOLS up, never at NONE, and the `--` refusal is a deny
// rule (which wins over allow) at every level.
func TestBoxRunPolicyFor_AgentPythonRules(t *testing.T) {
	none, _ := boxRunPolicyFor("none")
	build, _ := boxRunPolicyFor("build_tools")
	full, _ := boxRunPolicyFor("full_sudo")
	for _, r := range []string{
		"Bash(agent-python setup)", "Bash(agent-python setup *)",
		"Bash(agent-python test)", "Bash(agent-python test *)",
		"Bash(agent-python venv)", "Bash(agent-python venv *)",
	} {
		if !hasRule(build.Allowed, r) || !hasRule(full.Allowed, r) {
			t.Errorf("BUILD_TOOLS and FULL_SUDO must allow %q", r)
		}
		if hasRule(none.Allowed, r) {
			t.Errorf("NONE must not allow %q", r)
		}
	}
	for _, p := range []boxRunPolicy{none, build, full} {
		if !hasRule(p.Denied, "Bash(agent-python * -- *)") {
			t.Errorf("the `-- CMD` form must be denied at every level")
		}
		if !hasRule(p.Denied, "Bash(sudo agent-python * -- *)") {
			t.Errorf("the sudo-prefixed `-- CMD` form must be denied at every level")
		}
	}
}
