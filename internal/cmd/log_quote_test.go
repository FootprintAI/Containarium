package cmd

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"strconv"
	"strings"
	"testing"
)

// #3456: the startup account sync logs the usernames and box names it
// restored, skipped or could not restore. They are tenant names and are
// logged with %q, so a newline cannot start a forged log line and an ESC byte
// cannot reach the operator's terminal.
//
// The sync needs a live Incus, so this test reads every "[account-sync]"
// format string out of daemon.go and logs it the way the daemon does: a
// hostile name for each string verb, a count for %d and an error for %v.

// logQuoteHostile carries a newline followed by a forged log prefix, and an
// ANSI clear-screen sequence.
const logQuoteHostile = "evil\n[forged] admin login ok\x1b[2J"

// logQuoteEscaped is how logQuoteHostile reads once %q has escaped it.
const logQuoteEscaped = `evil\n[forged] admin login ok\x1b[2J`

// accountSyncFormats returns the format strings of the "[account-sync]"
// log.Printf calls in daemon.go.
func accountSyncFormats(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}
	var formats []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Printf" {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "log" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		format, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatalf("unquote %s: %v", lit.Value, err)
		}
		if strings.HasPrefix(format, "[account-sync]") {
			formats = append(formats, format)
		}
		return true
	})
	return formats
}

// hostileArgs builds one argument per verb in format: a count for %d, an
// error for %v and the hostile name for every string verb.
func hostileArgs(t *testing.T, format string) (args []any, names int) {
	t.Helper()
	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 >= len(format) {
			continue
		}
		switch format[i+1] {
		case '%':
		case 'd':
			args = append(args, 2)
		case 'v':
			args = append(args, errors.New("boom"))
		case 's', 'q':
			args = append(args, strings.Join([]string{"alice", logQuoteHostile}, ", "))
			names++
		default:
			t.Fatalf("unexpected verb %%%c in %q", format[i+1], format)
		}
		i++
	}
	return args, names
}

func TestLogQuote_AccountSyncNames(t *testing.T) {
	formats := accountSyncFormats(t)
	withNames := 0
	for _, format := range formats {
		args, names := hostileArgs(t, format)
		if names == 0 {
			continue
		}
		withNames++
		var buf bytes.Buffer
		log.New(&buf, "", 0).Printf(format, args...)
		out := buf.String()
		if strings.ContainsAny(out, "\x1b\r") {
			t.Fatalf("raw control byte in log output of %q: %q", format, out)
		}
		if strings.Count(out, "\n") != 1 {
			t.Fatalf("want one log line from %q, got %q", format, out)
		}
		if !strings.Contains(out, logQuoteEscaped) {
			t.Fatalf("hostile value not logged in escaped form by %q; got %q", format, out)
		}
	}
	// restored, revoked-skipped, all-revoked and failed.
	if withNames < 4 {
		t.Fatalf("want at least 4 account-sync log calls that name accounts, found %d in %q", withNames, formats)
	}
}
