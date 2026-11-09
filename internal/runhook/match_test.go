package runhook

import (
	"reflect"
	"testing"
)

func mustAllowlist(t *testing.T, entries ...string) Allowlist {
	t.Helper()
	a, err := ParseAllowlist(entries)
	if err != nil {
		t.Fatalf("ParseAllowlist(%q): %v", entries, err)
	}
	return a
}

func mustParse(t *testing.T, s string) Command {
	t.Helper()
	c, err := ParseCommand(s)
	if err != nil {
		t.Fatalf("ParseCommand(%q): %v", s, err)
	}
	return c
}

func TestParseCommand_WordsAndQuotes(t *testing.T) {
	c := mustParse(t, `go test -run 'Test A' "./pkg/x" a\ b`)
	want := []string{"go", "test", "-run", "Test A", "./pkg/x", "a b"}
	if !reflect.DeepEqual(c.Argv, want) || !c.Simple {
		t.Fatalf("argv = %q simple = %v, want %q simple", c.Argv, c.Simple, want)
	}
	if _, err := ParseCommand(`echo 'unterminated`); err == nil {
		t.Error("an unterminated quote must not parse")
	}
}

func TestParseCommand_LeadingAssignmentsAreDropped(t *testing.T) {
	c := mustParse(t, `GITHUB_TOKEN=ghp_secret FOO=1 go test ./...`)
	if !reflect.DeepEqual(c.Argv, []string{"go", "test", "./..."}) {
		t.Fatalf("argv = %q, want the assignments dropped", c.Argv)
	}
	if c.Assignments != 2 {
		t.Errorf("assignments = %d, want 2", c.Assignments)
	}
}

// Matching: a glob over argv elements; `*` within one element only; the
// executable name exactly; a shell operator never matches.
func TestAllowlist_Match(t *testing.T) {
	a := mustAllowlist(t, "go test *", "make lint", "npm run test:*", "kubectl get pods -n *")
	for _, tc := range []struct {
		cmd  string
		want bool
	}{
		{"go test ./...", true},
		{"go test ./a ./b", false},        // `*` does not span two elements
		{"go test", false},                // element count must agree
		{"go test 'a b'", true},           // one quoted element may hold a space
		{"make lint", true},               //
		{"make deploy", false},            //
		{"make lint extra", false},        //
		{"npm run test:unit", true},       // `*` inside an element
		{"npm run build", false},          //
		{"/usr/bin/go test ./...", false}, // the executable matches exactly
		{"kubectl get pods -n dev", true},
		{"go test ./...; rm -rf /", false},  // operators never match
		{"go test ./... && echo ok", false}, //
		{"go test ./... | tee x", false},    //
		{"go test $(cat list)", false},      // expansion
		{"go test `cat list`", false},       //
		{"go test ./... > out", false},      // redirection
		{"go test ${PKG}", false},           //
		{"FOO=1 go test ./...", false},      // an assignment changes what runs
		{"go test ./...\nrm x", false},      // newline is an operator
		{"go test (x)", false},              //
	} {
		c, err := ParseCommand(tc.cmd)
		got := err == nil && a.Match(c)
		if got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.cmd, got, tc.want)
		}
	}
}

func TestAllowlist_EntryExecutableHasNoWildcard(t *testing.T) {
	a := mustAllowlist(t, "g* test")
	if a.Match(mustParse(t, "go test")) {
		t.Error("a `*` in the executable element must be literal")
	}
}

func TestParseAllowlist_RefusesBadEntries(t *testing.T) {
	for _, e := range []string{"", "   ", "go test; rm", "go $(x)", "a > b", "FOO=1 go"} {
		if _, err := ParseAllowlist([]string{e}); err == nil {
			t.Errorf("entry %q must be refused", e)
		}
	}
	long := make([]byte, MaxAllowEntryBytes+1)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := ParseAllowlist([]string{string(long)}); err == nil {
		t.Error("an over-long entry must be refused")
	}
	many := make([]string, MaxAllowEntries+1)
	for i := range many {
		many[i] = "true"
	}
	if _, err := ParseAllowlist(many); err == nil {
		t.Error("too many entries must be refused")
	}
}

// The level's own rules (the engine's Bash(...) patterns) are evaluated the
// way the engine reads them: `*` matches any run of characters, spaces too.
func TestLevelRules_Match(t *testing.T) {
	allowed := []string{"Read", "Bash(git status)", "Bash(git status *)", "Bash(go test *)"}
	denied := []string{"Bash(git -C* push)", "Bash(git -C* push *)"}
	for _, tc := range []struct {
		cmd  string
		want bool
	}{
		{"git status", true},
		{"git status --short", true},
		{"go test ./a ./b", true},
		{"go build", false},
		{"rm -rf /", false},
	} {
		if got := levelAllows(allowed, denied, tc.cmd); got != tc.want {
			t.Errorf("levelAllows(%q) = %v, want %v", tc.cmd, got, tc.want)
		}
	}
	if levelAllows(append(allowed, "Bash(git -C* status)"), denied, "git -C x push") {
		t.Error("a deny rule must win over an allow rule")
	}
}

func TestParseAllowlist_RefusesInterpretersThatRunCallerCode(t *testing.T) {
	for _, e := range []string{
		"sh -c *", "bash -c", "bash -lc ls", "/bin/dash -c ls", "zsh -c ls", "python3 -c ls", "python3.12 -m http.server",
		"perl -e 1", "ruby -e 1", "node -e 1", "node --eval 1", "python3 *", "node *", "bash *",
	} {
		if _, err := ParseAllowlist([]string{e}); err == nil {
			t.Errorf("ParseAllowlist(%q) must be refused", e)
		}
	}
	for _, e := range []string{"python3 scripts/check.py", "node build.js", "make lint", "go test *", "bash"} {
		if _, err := ParseAllowlist([]string{e}); err != nil {
			t.Errorf("ParseAllowlist(%q) = %v, want accepted", e, err)
		}
	}
}
