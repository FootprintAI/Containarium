package cmd

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"strconv"
	"strings"
	"testing"
)

// #3456: the startup account sync logs the usernames it restored and the
// boxes it could not restore. Both lists are tenant names and are logged with
// %q, so a newline cannot start a forged log line and an ESC byte cannot reach
// the operator's terminal.
//
// The sync needs a live Incus, so this test reads the two format strings out
// of daemon.go and logs them with a hostile name, the way the daemon does.

// logQuoteHostile carries a newline followed by a forged log prefix, and an
// ANSI clear-screen sequence.
const logQuoteHostile = "evil\n[forged] admin login ok\x1b[2J"

// logQuoteEscaped is how logQuoteHostile reads once %q has escaped it.
const logQuoteEscaped = `evil\n[forged] admin login ok\x1b[2J`

// accountSyncNameFormats returns the format strings of the account-sync log
// calls in daemon.go that list names.
func accountSyncNameFormats(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}
	var formats []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 3 {
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
		join, ok := call.Args[2].(*ast.CallExpr)
		if !ok {
			return true
		}
		if js, ok := join.Fun.(*ast.SelectorExpr); ok && js.Sel.Name == "Join" && strings.HasPrefix(format, "[account-sync]") {
			formats = append(formats, format)
		}
		return true
	})
	return formats
}

func TestLogQuote_AccountSyncNameLists(t *testing.T) {
	formats := accountSyncNameFormats(t)
	if len(formats) != 2 {
		t.Fatalf("want the restored and failed account-sync log calls, found %d: %q", len(formats), formats)
	}
	for _, format := range formats {
		var buf bytes.Buffer
		logger := log.New(&buf, "", 0)
		logger.Printf(format, 2, strings.Join([]string{"alice", logQuoteHostile}, ", "))
		out := buf.String()
		if strings.ContainsAny(out, "\x1b\r") {
			t.Fatalf("raw control byte in log output: %q", out)
		}
		if strings.Count(out, "\n") != 1 {
			t.Fatalf("want one log line, got %q", out)
		}
		if !strings.Contains(out, logQuoteEscaped) {
			t.Fatalf("hostile value not logged in escaped form; got %q", out)
		}
	}
}
