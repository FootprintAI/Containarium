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

// accountSyncCall is one "[account-sync]" log.Printf call in daemon.go.
type accountSyncCall struct {
	format string
	args   []ast.Expr
}

// accountSyncCalls returns the "[account-sync]" log.Printf calls in daemon.go.
func accountSyncCalls(t *testing.T) []accountSyncCall {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}
	var calls []accountSyncCall
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
			calls = append(calls, accountSyncCall{format: format, args: call.Args[1:]})
		}
		return true
	})
	return calls
}

// isStringsJoin reports whether e is a call to strings.Join.
func isStringsJoin(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == "strings" && sel.Sel.Name == "Join"
}

// hostileArgs builds one argument per verb in format: a count for %d, an
// error for %v, a list of names (one of them hostile) for %q and %s, and a
// harmless string for any other verb (for example %x). Flags, width and
// precision between the % and the verb are skipped.
func hostileArgs(format string) (args []any, names int) {
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		for i < len(format) && strings.IndexByte("+-# 0123456789.*", format[i]) >= 0 {
			i++
		}
		if i >= len(format) {
			break
		}
		switch format[i] {
		case '%':
		case 'd':
			args = append(args, 2)
		case 'v':
			args = append(args, errors.New("boom"))
		case 's', 'q':
			args = append(args, []string{"alice", logQuoteHostile})
			names++
		default:
			args = append(args, "harmless")
		}
	}
	return args, names
}

func TestLogQuote_AccountSyncNames(t *testing.T) {
	calls := accountSyncCalls(t)
	withNames := 0
	for _, c := range calls {
		format := c.format
		// #3476: pass the slice itself to %q so each name stays delimited;
		// quoting strings.Join(list, ", ") runs the names together.
		for _, a := range c.args {
			if isStringsJoin(a) {
				t.Fatalf("%q passes strings.Join to a log verb; pass the slice to %%q instead", format)
			}
		}
		args, names := hostileArgs(format)
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
		if !strings.Contains(out, `"alice" "`+logQuoteEscaped+`"`) {
			t.Fatalf("hostile value not logged as separately quoted names by %q; got %q", format, out)
		}
	}
	// restored, revoked-skipped, all-revoked and failed.
	if withNames < 4 {
		t.Fatalf("want at least 4 account-sync log calls that name accounts, found %d in %d calls", withNames, len(calls))
	}
}
