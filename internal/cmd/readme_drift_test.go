//go:build !containarium_client

package cmd

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/spf13/cobra"
)

// README drift guard (#2244). The README's shell blocks are the first thing a
// new user copies; a renamed verb or a dropped flag there is a broken first
// run that no other test sees. These tests parse every fenced bash/sh/shell
// block in README.md and assert each `containarium <verb> [--flag]` resolves
// in the real cobra command tree, and that every in-page `(#anchor)` link
// points at a heading that exists.
//
// Untagged-build only (!containarium_client): on a host the installer links
// `containarium` -> `containariumd`, so a README invocation is valid if
// containariumd has it. The client tree is a strict subset of that one
// (TestContainariumdCommandTree_SupersetOfClientGolden), so checking the
// superset is the right bound for a document that covers both.

const readmePath = "../../README.md"

// cliInvocation is one `containarium …` command found in a fenced shell
// block: the words after the binary name, and where it was found.
type cliInvocation struct {
	Line int      // 1-based line of the command's first line in the file
	Args []string // shell words after `containarium`
}

// driftProblem is one invocation (or link) that doesn't resolve.
type driftProblem struct {
	Line   int
	Detail string
}

// shellFenceLangs are the fence info strings whose contents are treated as
// commands. Unlabelled fences (illustrative output, the verb table) and
// jsonc/ssh-config blocks are deliberately not checked.
var shellFenceLangs = map[string]bool{"bash": true, "sh": true, "shell": true}

// fenceInfo reports whether line opens/closes a code fence, and the info
// string's first word (lowercased) when it does.
func fenceInfo(line string) (bool, string) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "```") && !strings.HasPrefix(t, "~~~") {
		return false, ""
	}
	info := strings.Fields(strings.TrimLeft(t, "`~"))
	if len(info) == 0 {
		return true, ""
	}
	return true, strings.ToLower(info[0])
}

// extractCLIInvocations returns every `containarium …` command in the
// document's shell fences, with backslash continuations joined, comments
// dropped, and pipelines / `&&` / `;` / `$(…)` split into separate commands.
func extractCLIInvocations(markdown string) []cliInvocation {
	var out []cliInvocation
	inFence, shell := false, false
	var logical strings.Builder
	start := 0

	for i, line := range strings.Split(markdown, "\n") {
		if isFence, lang := fenceInfo(line); isFence {
			if !inFence {
				inFence, shell = true, shellFenceLangs[lang]
			} else {
				inFence, shell = false, false
			}
			continue
		}
		if !inFence || !shell {
			continue
		}
		if logical.Len() == 0 {
			start = i + 1
		}
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, "\\") {
			logical.WriteString(strings.TrimSuffix(trimmed, "\\"))
			logical.WriteByte(' ')
			continue
		}
		logical.WriteString(trimmed)
		for _, words := range splitShell(logical.String()) {
			if args, ok := containariumArgs(words); ok {
				out = append(out, cliInvocation{Line: start, Args: args})
			}
		}
		logical.Reset()
	}
	return out
}

// containariumArgs strips the prefixes a README puts before the binary
// (`sudo`, `VAR=value`, `env`) and returns the words after `containarium`.
func containariumArgs(words []string) ([]string, bool) {
	i := 0
	for i < len(words) {
		w := words[i]
		switch {
		case w == "sudo" || w == "env" || w == "exec" || w == "time":
			i++
		case i > 0 && words[i-1] == "sudo" && strings.HasPrefix(w, "-"):
			i++
		case isEnvAssignment(w):
			i++
		default:
			if w == "containarium" {
				return words[i+1:], true
			}
			return nil, false
		}
	}
	return nil, false
}

func isEnvAssignment(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for j, r := range w[:eq] {
		if !(r == '_' || unicode.IsLetter(r) || (j > 0 && unicode.IsDigit(r))) {
			return false
		}
	}
	return true
}

// splitShell is a deliberately small shell word splitter: enough for README
// snippets, not a shell. It honours quotes and backslashes, drops `#`
// comments, ends a command at | ; & ( ), and lifts each `$(…)` out as a
// command of its own (the substitution stays in the outer word verbatim).
func splitShell(s string) [][]string {
	var segs [][]string
	var words []string
	var cur strings.Builder
	inWord := false
	flushWord := func() {
		if inWord {
			words = append(words, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	flushSeg := func() {
		flushWord()
		if len(words) > 0 {
			segs = append(segs, words)
			words = nil
		}
	}
	// substitution handles a `$(` at s[i]; returns the index of its `)`.
	substitution := func(i int) int {
		end := matchParen(s, i+1)
		segs = append(segs, splitShell(s[i+2:end])...)
		cur.WriteString(s[i:min(end+1, len(s))])
		return end
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(s[i+1])
			i++
			inWord = true
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				j = len(s) - i - 1
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
			inWord = true
		case c == '"':
			for i++; i < len(s) && s[i] != '"'; i++ {
				switch {
				case s[i] == '\\' && i+1 < len(s):
					cur.WriteByte(s[i+1])
					i++
				case s[i] == '$' && i+1 < len(s) && s[i+1] == '(':
					i = substitution(i)
				default:
					cur.WriteByte(s[i])
				}
			}
			inWord = true
		case c == '$' && i+1 < len(s) && s[i+1] == '(':
			i = substitution(i)
			inWord = true
		case c == '#' && !inWord:
			flushSeg()
			return segs
		case c == ' ' || c == '\t':
			flushWord()
		case c == '|' || c == ';' || c == '&' || c == '(' || c == ')':
			flushSeg()
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	flushSeg()
	return segs
}

// matchParen returns the index of the `)` closing the `(` at s[open], or
// len(s) when it is unbalanced.
func matchParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(s)
}

// lookupFlag finds a long (--name) or short (-n) flag on cmd, including the
// persistent flags it inherits. It reports whether the flag exists and
// whether it consumes the next word as its value.
func lookupFlag(cmd *cobra.Command, token string) (found, takesValue bool) {
	inherited := cmd.InheritedFlags() // also merges persistent flags into Flags()
	if strings.HasPrefix(token, "--") {
		name, _, hasEq := strings.Cut(token[2:], "=")
		if name == "help" {
			return true, false
		}
		f := cmd.Flags().Lookup(name)
		if f == nil {
			f = inherited.Lookup(name)
		}
		if f == nil {
			return false, false
		}
		return true, !hasEq && f.NoOptDefVal == ""
	}
	short := token[1:2]
	if short == "h" {
		return true, false
	}
	f := cmd.Flags().ShorthandLookup(short)
	if f == nil {
		f = inherited.ShorthandLookup(short)
	}
	if f == nil {
		return false, false
	}
	return true, len(token) == 2 && f.NoOptDefVal == ""
}

// checkInvocation walks inv down the command tree: leading words must name
// subcommands until a runnable command takes positional arguments, and
// every flag must exist on the command it is given to.
func checkInvocation(root *cobra.Command, inv cliInvocation) []driftProblem {
	var out []driftProblem
	cmd, path, descending := root, "containarium", true

	for i := 0; i < len(inv.Args); i++ {
		a := inv.Args[i]
		if a == "--" || cmd.DisableFlagParsing {
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			found, takesValue := lookupFlag(cmd, a)
			if !found {
				name, _, _ := strings.Cut(a, "=")
				out = append(out, driftProblem{inv.Line, fmt.Sprintf("`%s` has no flag %q", path, name)})
				continue
			}
			if takesValue {
				i++
			}
			continue
		}
		if !descending {
			continue
		}
		if child := findSubcommand(cmd, a); child != nil {
			cmd, path = child, path+" "+a
			continue
		}
		if cmd == root || !cmd.Runnable() {
			out = append(out, driftProblem{inv.Line, fmt.Sprintf("`%s` has no subcommand %q", path, a)})
			return out
		}
		descending = false // first positional argument of a runnable command
	}
	return out
}

func findSubcommand(cmd *cobra.Command, name string) *cobra.Command {
	for _, c := range cmd.Commands() {
		if c.Name() == name || c.HasAlias(name) {
			return c
		}
	}
	if name == "help" || name == "completion" {
		return &cobra.Command{Use: name, Run: func(*cobra.Command, []string) {}}
	}
	return nil
}

var (
	headingRE    = regexp.MustCompile(`^#{1,6}\s+(.+?)\s*#*\s*$`)
	htmlAnchorRE = regexp.MustCompile(`<a\s+(?:id|name)="([^"]+)"`)
	anchorLinkRE = regexp.MustCompile(`\]\(#([^)\s]+)\)`)
)

// githubSlug mirrors how GitHub derives a heading's anchor: lowercase, keep
// letters, digits, '-' and '_', turn spaces into '-', drop everything else.
func githubSlug(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}

// checkAnchors reports every in-page link (`](#x)`) outside code fences
// whose target is not a heading (or explicit <a id/name>) in the document.
func checkAnchors(markdown string) []driftProblem {
	lines := strings.Split(markdown, "\n")
	targets := map[string]bool{}
	seen := map[string]int{}
	inFence := false
	for _, line := range lines {
		if isFence, _ := fenceInfo(line); isFence {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if m := headingRE.FindStringSubmatch(line); m != nil {
			slug := githubSlug(m[1])
			if n := seen[slug]; n > 0 {
				targets[fmt.Sprintf("%s-%d", slug, n)] = true
			} else {
				targets[slug] = true
			}
			seen[slug]++
		}
		for _, m := range htmlAnchorRE.FindAllStringSubmatch(line, -1) {
			targets[m[1]] = true
		}
	}

	var out []driftProblem
	inFence = false
	for i, line := range lines {
		if isFence, _ := fenceInfo(line); isFence {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		for _, m := range anchorLinkRE.FindAllStringSubmatch(line, -1) {
			if !targets[strings.ToLower(m[1])] {
				out = append(out, driftProblem{i + 1, fmt.Sprintf("link to #%s has no matching heading", m[1])})
			}
		}
	}
	return out
}

// checkMarkdown runs both checks over one document.
func checkMarkdown(root *cobra.Command, markdown string) []driftProblem {
	var out []driftProblem
	for _, inv := range extractCLIInvocations(markdown) {
		out = append(out, checkInvocation(root, inv)...)
	}
	return append(out, checkAnchors(markdown)...)
}

func readDriftFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestREADMECommandsAndAnchorsResolve(t *testing.T) {
	md := readDriftFile(t, readmePath)
	if n := len(extractCLIInvocations(md)); n < 10 {
		t.Fatalf("found only %d containarium invocations in %s — the extractor is broken, not the README", n, readmePath)
	}
	for _, p := range checkMarkdown(rootCmd, md) {
		t.Errorf("README.md:%d: %s", p.Line, p.Detail)
	}
}

// The bad fixture proves the drift test can fail: every planted mistake must
// be reported, by line.
func TestREADMEDriftChecker_CatchesBadFixture(t *testing.T) {
	md := readDriftFile(t, "testdata/readme_drift/bad.md")
	got := checkMarkdown(rootCmd, md)

	want := []struct {
		line int
		sub  string
	}{
		{11, `"--no-such-flag"`},
		{14, `"frobnicate"`},
		{17, `"synchronise"`},
		{20, `"--definitely-not-a-flag"`},
		{25, `#no-such-section`},
	}
	for _, w := range want {
		found := false
		for _, p := range got {
			if p.Line == w.line && strings.Contains(p.Detail, w.sub) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("bad.md:%d: expected a problem mentioning %s; got %+v", w.line, w.sub, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("expected exactly %d problems, got %d: %+v", len(want), len(got), got)
	}
}

func TestREADMEDriftChecker_AcceptsGoodFixture(t *testing.T) {
	md := readDriftFile(t, "testdata/readme_drift/good.md")
	if n := len(extractCLIInvocations(md)); n != 4 {
		t.Errorf("expected 4 containarium invocations in good.md, got %d: %+v", n, extractCLIInvocations(md))
	}
	for _, p := range checkMarkdown(rootCmd, md) {
		t.Errorf("good.md:%d: unexpected problem: %s", p.Line, p.Detail)
	}
}

func TestExtractCLIInvocations(t *testing.T) {
	tests := []struct {
		name string
		md   string
		want [][]string
	}{
		{
			name: "plain",
			md:   "```bash\ncontainarium list\n```\n",
			want: [][]string{{"list"}},
		},
		{
			name: "continuation, sudo and env prefix",
			md:   "```bash\nsudo FOO=1 containarium create a \\\n  --cpu 4\n```\n",
			want: [][]string{{"create", "a", "--cpu", "4"}},
		},
		{
			name: "comment stripped, quotes kept as one word",
			md:   "```sh\ncontainarium code run a --prompt \"add # tests\" # --nope\n```\n",
			want: [][]string{{"code", "run", "a", "--prompt", "add # tests"}},
		},
		{
			name: "pipeline and command substitution",
			md:   "```shell\nX=\"$(containarium token generate --username a)\" && containarium list | grep a\n```\n",
			want: [][]string{{"token", "generate", "--username", "a"}, {"list"}},
		},
		{
			name: "non-shell fence ignored",
			md:   "```\ncontainarium list\n```\n```jsonc\ncontainarium list\n```\n",
			want: nil,
		},
		{
			name: "containariumd is not checked",
			md:   "```bash\ncontainariumd daemon --runtime=k8s\n```\n",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCLIInvocations(tt.md)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d invocations %+v, want %d %v", len(got), got, len(tt.want), tt.want)
			}
			for i := range got {
				if strings.Join(got[i].Args, "\x00") != strings.Join(tt.want[i], "\x00") {
					t.Errorf("invocation %d: got %q, want %q", i, got[i].Args, tt.want[i])
				}
			}
		})
	}
}

func TestGitHubHeadingSlug(t *testing.T) {
	tests := []struct{ heading, want string }{
		{"Quick start", "quick-start"},
		{"`containarium` CLI", "containarium-cli"},
		{"vs. SaaS-only sandboxes (e2b, Modal, Replit)", "vs-saas-only-sandboxes-e2b-modal-replit"},
		{"Kubernetes backend (experimental)", "kubernetes-backend-experimental"},
		{"1. Install, then create your first box", "1-install-then-create-your-first-box"},
		{"Two binaries: `containarium` vs `containariumd`", "two-binaries-containarium-vs-containariumd"},
	}
	for _, tt := range tests {
		if got := githubSlug(tt.heading); got != tt.want {
			t.Errorf("githubSlug(%q) = %q, want %q", tt.heading, got, tt.want)
		}
	}
}
