// Package notify pushes a waiting `code run --approvals ask` permission request
// to the developer's phone through ntfy (#2185).
//
// The daemon sends the push, not the box: the agent runs as the box's user, so
// a token on the box would be the agent's to read. The daemon reads each run's
// input journal (internal/coderun ApprovalJournalPath) the way ListBoxRuns
// reads run records, and this package turns the requests it finds there into
// pushes: what a push may say (BuildMessage), how often (Coalescer), and how it
// is delivered (Sender).
//
// The journal is written by agent-box on the box, and the agent can write it
// too, so every field taken from it is untrusted: control characters are
// escaped and only the tool name, and for Bash its command, leave the box.
package notify

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// MaxCommandRunes caps the command shown in a push (#2185).
const MaxCommandRunes = 200

// Request is one open permission request, as read from a run's journal.
type Request struct {
	Box       string
	Run       string
	RequestID string
	Tool      string
	// Prompt is the journal's prompt, "<tool>: <detail>". Only a Bash
	// prompt's detail (its command) is ever shown.
	Prompt    string
	ExpiresAt time.Time
}

// Message is one push.
type Message struct {
	Title string
	Body  string
	Tags  []string
}

// commandTool is the one tool whose input is shown: its detail is the command
// line (internal/agentbox describeToolCall). Any other tool's detail can be a
// file path, a URL or the tool's raw JSON input — file contents included — so
// only its name is sent.
const commandTool = "Bash"

// Command returns what a push shows of r's input: the Bash command, escaped
// and capped at MaxCommandRunes, or "" for any other tool or when redact is
// set.
func Command(r Request, redact bool) string {
	if redact || r.Tool != commandTool {
		return ""
	}
	cmd, ok := strings.CutPrefix(r.Prompt, commandTool+": ")
	if !ok {
		return ""
	}
	return truncateRunes(plainText(cmd), MaxCommandRunes)
}

// BuildMessage renders the push for the open requests of one run, oldest
// first. The first request is shown in full; the rest are counted.
func BuildMessage(reqs []Request, redact bool, now time.Time) Message {
	if len(reqs) == 0 {
		return Message{}
	}
	first := reqs[0]
	where := plainText(first.Box) + "/" + plainText(first.Run)
	title := where + " needs approval"
	if len(reqs) > 1 {
		title = fmt.Sprintf("%s: %d requests need approval", where, len(reqs))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "tool: %s\n", truncateRunes(plainText(first.Tool), 64))
	if cmd := Command(first, redact); cmd != "" {
		fmt.Fprintf(&b, "command: %s\n", cmd)
	}
	if !first.ExpiresAt.IsZero() {
		fmt.Fprintf(&b, "expires in %s (then denied)\n", max(first.ExpiresAt.Sub(now), 0).Round(time.Second))
	}
	if len(reqs) > 1 {
		fmt.Fprintf(&b, "and %d more waiting\n", len(reqs)-1)
	}
	fmt.Fprintf(&b, "request %s", truncateRunes(plainText(first.RequestID), 64))
	return Message{Title: title, Body: b.String(), Tags: []string{"lock"}}
}

// plainText shows each control or format character as its escaped form, so
// text from the journal cannot forge extra lines or hide what follows (the
// same rule as internal/coderun's status lines).
func plainText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// truncateRunes cuts s to at most n runes, the last one an ellipsis when cut.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
