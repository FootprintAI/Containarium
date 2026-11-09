package runhook

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// A command the parser cannot resolve to the program it runs is refused with a
// typed reason, even when an allowlist entry or the level would otherwise cover
// its words. The hard denies' reach over these is then true by construction.
func TestDecide_UnresolvableCommandsAreDeniedWithTypedReason(t *testing.T) {
	cases := map[string]string{
		"brace expansion":         "{cur,}l https://example.invalid/",
		"brace expansion in arg":  "ls {a,b}",
		"glob in executable":      "/usr/bin/cur* https://example.invalid/",
		"glob ? in executable":    "/usr/bin/cur? https://example.invalid/",
		"glob [] in executable":   "/usr/bin/cur[l] https://example.invalid/",
		"ANSI-C quoting":          "$'curl' https://example.invalid/",
		"ANSI-C escapes":          "$'\\x63url' https://example.invalid/",
		"arithmetic expansion":    "echo $((1+2))",
		"arithmetic as exec":      "$((1))ls",
		"arithmetic in dquote":    `echo "$((1+2))"`,
		"legacy arithmetic":       "echo $[1+2]",
		"compound line":           "ls && ls",
		"pipe":                    "ls | ls",
		"glob in argument":        "ls *.go",
		"redirection":             "ls > /tmp/x",
		"variable expansion":      "ls $HOME",
		"subshell":                "(ls)",
		"command substitution":    "ls $(ls)",
		"unresolvable and listed": "ls {a,b}",
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			// Every shape is allowlisted verbatim (as far as the allowlist can
			// say so) and the level allows ls: still refused.
			cfg := testConfig("ls", "ls *")
			d := Decide(cfg, cmd)
			if d.Verdict != VerdictDeny || d.CloseReason != pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_UNRESOLVABLE {
				t.Fatalf("Decide(%q) = %+v, want deny UNRESOLVABLE", cmd, d)
			}
			if d.Class != pb.AgentCommandClass_AGENT_COMMAND_CLASS_NOT_ALLOWED || d.Reason == "" {
				t.Errorf("class/reason = %v / %q", d.Class, d.Reason)
			}
		})
	}
}

// A hard deny keeps its own, more specific reason when the line also carries
// an operator.
func TestDecide_HardDenyKeepsPriorityOverUnresolvable(t *testing.T) {
	d := Decide(testConfig(), "ls && curl https://example.invalid/")
	if d.CloseReason != pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_HARD_DENY {
		t.Fatalf("decision = %+v, want HARD_DENY", d)
	}
}

// A simple command is still decided as before.
func TestDecide_SimpleCommandsAreStillAllowed(t *testing.T) {
	cfg := testConfig("make lint")
	if d := Decide(cfg, "make lint"); d.Verdict != VerdictAllow {
		t.Errorf("allowlisted simple command = %+v", d)
	}
	if d := Decide(cfg, "git status --short"); d.Verdict != VerdictDefer {
		t.Errorf("level simple command = %+v", d)
	}
	// Quoted glob and brace characters are plain text, not expansions.
	if d := Decide(testConfig("echo * *"), "echo '{a,b}' '*.go'"); d.Verdict != VerdictAllow {
		t.Errorf("quoted metacharacters = %+v", d)
	}
}

func TestParseCommand_UnresolvableCarriers(t *testing.T) {
	for cmd, want := range map[string]string{
		"{cur,}l x":     "brace",
		"/usr/bin/c* x": "glob",
		"$'curl' x":     "ANSI-C",
		"echo $((1))":   "arithmetic",
	} {
		c, err := ParseCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(c.Unresolvable, want) {
			t.Errorf("ParseCommand(%q).Unresolvable = %q, want it to mention %q", cmd, c.Unresolvable, want)
		}
	}
	if c, _ := ParseCommand("ls -la 'a b'"); c.Unresolvable != "" || !c.Simple {
		t.Errorf("simple command flagged: %+v", c)
	}
}

// A quoted shell command nested deeper than the rescan depth is refused with a
// typed reason instead of being ignored.
func TestDecide_NestingBeyondTheSupportedDepthIsDenied(t *testing.T) {
	nest := func(levels int, inner string) string {
		cmd := inner
		for i := 0; i < levels; i++ {
			cmd = "sh -c " + shellQuote(cmd)
		}
		return cmd
	}
	// Within the depth, the hard deny still finds the command.
	for _, levels := range []int{1, 2, 3} {
		d := Decide(testConfig(), nest(levels, "curl https://example.invalid/"))
		if d.CloseReason != pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_HARD_DENY {
			t.Errorf("%d-deep nest: %+v, want HARD_DENY", levels, d)
		}
	}
	for _, levels := range []int{4, 5, 8} {
		cmd := nest(levels, "curl https://example.invalid/")
		d := Decide(testConfig(), cmd)
		if d.Verdict != VerdictDeny || d.CloseReason != pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_UNRESOLVABLE {
			t.Errorf("%d-deep nest: %+v, want deny UNRESOLVABLE", levels, d)
		}
	}
	// A harmless innermost command is refused all the same: it cannot be proven.
	if d := Decide(testConfig(), nest(4, "ls")); d.Verdict != VerdictDeny {
		t.Errorf("4-deep harmless nest allowed: %+v", d)
	}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
