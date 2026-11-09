// Package runhook is the command allowlist, hard denies and audit events of
// agent runs (#3582): the engine's PreToolUse and PostToolUse hooks
// (`agent-box permission-hook pre|post`), the root-run sink that is the only
// writer of a run's audit file (`agent-box run-audit-sink`), and the pure
// matching, deny and redaction rules both use.
package runhook

import (
	"fmt"
	"strings"
)

// MaxAllowEntries and MaxAllowEntryBytes bound an allowlist.
const (
	MaxAllowEntries    = 256
	MaxAllowEntryBytes = 512
)

// Command is a shell command line split into words the way a POSIX shell
// would, without running or expanding anything.
type Command struct {
	// Argv is the first simple command's words, minus leading NAME=value
	// assignments. It is what an allowlist entry is matched against, and is
	// meaningful for matching only when Simple.
	Argv []string
	// Simple is false when the line holds a shell operator (; & | newline),
	// a redirection, a subshell, an expansion ($, backticks) or an unquoted
	// glob character: then what runs is not exactly Argv.
	Simple bool
	// Assignments is the number of leading NAME=value words dropped from Argv.
	Assignments int
	// Segments are the words of every simple command on the line (the words of
	// a command substitution are a segment of their own). Hard denies scan all
	// of them. Redirection targets are left out.
	Segments [][]string
	// Log is every word of the line in order with operators as their own
	// elements and each segment's leading assignments dropped: what an audit
	// event records (after redaction).
	Log []string
}

// ParseCommand splits s into words. An unterminated quote is an error.
func ParseCommand(s string) (Command, error) {
	c := Command{Simple: true}
	var (
		raw      []logTok
		seg      []string
		word     strings.Builder
		inWord   bool
		redirect bool // the next word is a redirection target
	)
	endWord := func() {
		if !inWord {
			return
		}
		w := word.String()
		word.Reset()
		inWord = false
		if redirect {
			redirect = false
			raw = append(raw, logTok{text: w, target: true})
			return
		}
		raw = append(raw, logTok{text: w})
		seg = append(seg, w)
	}
	endSeg := func(op string) {
		endWord()
		if len(seg) > 0 {
			c.Segments = append(c.Segments, seg)
		}
		seg = nil
		if op != "" {
			c.Simple = false
		}
	}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == ' ' || r == '\t':
			endWord()
		case r == '\\':
			if i+1 < len(rs) {
				i++
				if rs[i] != '\n' {
					word.WriteRune(rs[i])
					inWord = true
				}
			}
		case r == '\'':
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				j++
			}
			if j >= len(rs) {
				return Command{}, fmt.Errorf("unterminated single quote")
			}
			word.WriteString(string(rs[i+1 : j]))
			inWord = true
			i = j
		case r == '"':
			j := i + 1
			for ; j < len(rs) && rs[j] != '"'; j++ {
				switch {
				case rs[j] == '\\' && j+1 < len(rs) && strings.ContainsRune("$`\"\\\n", rs[j+1]):
					j++
					if rs[j] != '\n' {
						word.WriteRune(rs[j])
					}
					continue
				case rs[j] == '$' || rs[j] == '`':
					c.Simple = false
				}
				word.WriteRune(rs[j])
			}
			if j >= len(rs) {
				return Command{}, fmt.Errorf("unterminated double quote")
			}
			inWord = true
			i = j
		case r == '<' || r == '>':
			endWord()
			c.Simple = false
			op := string(r)
			for i+1 < len(rs) && strings.ContainsRune("<>&|", rs[i+1]) {
				i++
				op += string(rs[i])
			}
			raw = append(raw, logTok{text: op, op: true})
			redirect = true
		case r == ';' || r == '&' || r == '|' || r == '\n' || r == '(' || r == ')' || r == '`':
			op := string(r)
			for i+1 < len(rs) && (rs[i+1] == r && r != '(' && r != ')' && r != '`') {
				i++
				op += string(rs[i])
			}
			endSeg(op)
			raw = append(raw, logTok{text: op, op: true})
		case r == '$':
			c.Simple = false
			if i+1 < len(rs) && rs[i+1] == '(' {
				i++
				endSeg("$(")
				raw = append(raw, logTok{text: "$(", op: true})
				continue
			}
			word.WriteRune(r)
			inWord = true
		case r == '*' || r == '?' || r == '[' || r == '{' || (r == '~' && !inWord):
			c.Simple = false
			word.WriteRune(r)
			inWord = true
		default:
			word.WriteRune(r)
			inWord = true
		}
	}
	endSeg("")
	if len(c.Segments) > 1 {
		c.Simple = false
	}
	// Drop each segment's leading assignments: they are never matched as
	// the executable and never logged.
	for i, sg := range c.Segments {
		n := leadingAssignments(sg)
		if i == 0 {
			c.Assignments = n
			c.Argv = append([]string(nil), sg[n:]...)
		}
		c.Segments[i] = sg[n:]
	}
	c.Log = buildLog(raw)
	return c, nil
}

// buildLog drops, from the raw token stream (words, operators, redirection
// targets in order), the assignment words that lead a command: at the start
// and after each command operator.
func buildLog(raw []logTok) []string {
	var out []string
	leading := true
	for _, t := range raw {
		switch {
		case t.op:
			out = append(out, t.text)
			leading = !strings.ContainsAny(t.text, "<>")
		case leading && !t.target && isAssignment(t.text):
			// dropped
		default:
			if !t.target {
				leading = false
			}
			out = append(out, t.text)
		}
	}
	return out
}

type logTok struct {
	text   string
	op     bool
	target bool
}

func isAssignment(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for i, r := range w[:eq] {
		ok := r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9'
		if !ok {
			return false
		}
	}
	return true
}

func leadingAssignments(words []string) int {
	n := 0
	for n < len(words) && isAssignment(words[n]) {
		n++
	}
	return n
}

// Allowlist is a parsed org allowlist.
type Allowlist struct {
	entries [][]string
}

// ParseAllowlist parses entries. Each must be a non-empty simple command
// (no operator, expansion or assignment); `*` is the only wildcard, and it is
// literal in the executable element. Over-long or too many entries are refused.
func ParseAllowlist(entries []string) (Allowlist, error) {
	if len(entries) > MaxAllowEntries {
		return Allowlist{}, fmt.Errorf("allowlist has %d entries, at most %d are allowed", len(entries), MaxAllowEntries)
	}
	var a Allowlist
	for _, e := range entries {
		if len(e) > MaxAllowEntryBytes {
			return Allowlist{}, fmt.Errorf("allowlist entry is over %d bytes", MaxAllowEntryBytes)
		}
		if strings.TrimSpace(e) == "" {
			return Allowlist{}, fmt.Errorf("allowlist entry is empty")
		}
		if strings.ContainsAny(e, ";&|<>()`$\n\\'\"") {
			return Allowlist{}, fmt.Errorf("allowlist entry %q holds a shell operator, quote or expansion", e)
		}
		words := strings.Fields(e)
		if isAssignment(words[0]) {
			return Allowlist{}, fmt.Errorf("allowlist entry %q starts with an assignment", e)
		}
		a.entries = append(a.entries, words)
	}
	return a, nil
}

// Match reports whether c matches an entry: same number of elements, the
// executable equal, every other element matched by its pattern, where `*`
// matches any run of characters inside that one element. A command that is
// not simple, or that starts with an assignment, never matches.
func (a Allowlist) Match(c Command) bool {
	if !c.Simple || c.Assignments > 0 || len(c.Argv) == 0 {
		return false
	}
	for _, e := range a.entries {
		if len(e) != len(c.Argv) || e[0] != c.Argv[0] {
			continue
		}
		ok := true
		for i := 1; i < len(e) && ok; i++ {
			ok = globMatch(e[i], c.Argv[i])
		}
		if ok {
			return true
		}
	}
	return false
}

// globMatch matches s against p, where `*` is any run of characters (possibly
// empty) and every other character is literal.
func globMatch(p, s string) bool {
	// Iterative wildcard match with backtracking to the last star.
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case pi < len(p) && p[pi] == s[si]:
			pi++
			si++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// levelAllows evaluates the run's tool-access level the way the engine reads
// its Bash(...) rules: `*` matches any run of characters, spaces included, and
// a deny rule wins over an allow rule. Rules for other tools are ignored.
func levelAllows(allowed, denied []string, command string) bool {
	command = strings.TrimSpace(command)
	match := func(rules []string) bool {
		for _, r := range rules {
			if !strings.HasPrefix(r, "Bash(") || !strings.HasSuffix(r, ")") {
				continue
			}
			if globMatch(r[len("Bash("):len(r)-1], command) {
				return true
			}
		}
		return false
	}
	return !match(denied) && match(allowed)
}
