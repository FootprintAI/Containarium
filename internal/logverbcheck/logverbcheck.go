// Package logverbcheck keeps tenant-controlled strings from reaching logs
// and CLI tables unescaped (#3457, follow-up to #3455, #3456 and #3448).
//
// A tenant value that contains "\n" can forge a log line, and one that
// contains ESC can drive the operator's terminal. The fix is to log such a
// value with %q, and to route a CLI table cell through escapeControl. This
// package finds the places that regress: a value whose name is in
// TenantFields, handed to %s or %v in
//
//   - a log call: log.Printf / Fatalf / Panicf, the print forms log.Print /
//     Println / Fatal / Panic (which never escape), and printf-style logger
//     methods (Printf, Logf/logf, Infof, Warnf, ...) on any receiver other
//     than fmt, errors and status;
//   - a table row in internal/cmd: fmt.Printf or fmt.Fprintf whose format
//     has a tab or a width-padded verb (%-25s), or whose writer is a
//     *tabwriter.Writer.
//
// It works on the syntax tree only (go/parser, no type checking), so it
// needs no module downloads. A value is matched by its terminal name: the
// identifier, the selector's field (req.Username -> Username), the proto
// getter with Get stripped (req.GetUsername() -> Username), or either side
// of a "+" concatenation. Matching is case-insensitive. A file-local
// constant is never matched, and neither is a value wrapped in a call
// (escapeControl(name), len(name), strconv.Quote(name)).
//
// fmt.Errorf / status.Errorf are out of scope: whether a wrapped error should
// quote what it carries is a separate decision (#3472).
package logverbcheck

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// TenantFields is the one table of value names the check treats as
// tenant-controlled, keyed by lower-cased terminal name. Each entry says
// where the value comes from. The set follows the classification in #3468
// (internal/server) and #3473 (sentinel, gateway, app, core). Generic names
// such as "name", "id" or "key" are deliberately absent: repo-wide they name
// operator values (backends, pools, config keys) far more often than tenant
// ones, and the per-package tests in internal/server and friends already pin
// those call sites.
var TenantFields = map[string]string{
	// Box / container names: chosen by the tenant at create time.
	"container":       "box/container name",
	"containername":   "box/container name",
	"targetcontainer": "box/container name (move target)",
	"box":             "box/container name",
	"boxname":         "box/container name",

	// Users and accounts: chosen by the tenant or the connecting client.
	"username":    "tenant username",
	"user":        "tenant or in-box user name",
	"owner":       "owner username",
	"accountname": "account name",
	"releasedby":  "username that released a box",
	"keyowner":    "owner of a model-gateway key",
	"tenant":      "tenant name",

	// SSH login: picked by an unauthenticated SSH client.
	"sshuser":   "SSH login user",
	"sshlogin":  "SSH login user",
	"loginuser": "SSH login user",

	// Labels: keys and values from the request body.
	"labelkey":   "label key",
	"labelvalue": "label value",

	// Projects (tracker, cloud project names supplied by the tenant).
	"project":     "project name",
	"projectname": "project name",

	// Processes running inside a tenant box.
	"comm":        "process name (in-box comm)",
	"processname": "process name",

	// Models: the tenant picks the model id, the upstream reports it.
	"model":     "model name",
	"modelname": "model name",
	"modelid":   "model id",

	// Apps and routes the tenant names.
	"appname":    "app name",
	"subdomain":  "app subdomain",
	"fulldomain": "route domain",

	// Skills and tunnels (external catalogs, tunnelled spots).
	"skill":   "skill id from an external catalog",
	"skillid": "skill id from an external catalog",
	"spotid":  "tunnel spot id (handshake checks only non-empty)",
}

// unsafeVerbs are the verbs that print a string argument unescaped.
const unsafeVerbs = "sv"

// Finding is one tenant value handed to an unescaped verb.
type Finding struct {
	Pos  token.Position
	Expr string // source form of the argument, e.g. "req.Username"
	Verb string // "%s", "%v", or "print" for a print-style log call
	Kind string // "log" or "table"
}

func (f Finding) String() string {
	if f.Verb == "print" {
		return fmt.Sprintf("%s: %s logged by a print-style call; use log.Printf with %%q (#3457)", f.Pos, f.Expr)
	}
	what, fix := "logged with "+f.Verb, "use %q"
	if f.Kind == "table" {
		what, fix = "printed in a CLI table with "+f.Verb, "wrap it in escapeControl or use %q"
	}
	return fmt.Sprintf("%s: tenant-controlled %s %s; %s (#3457)", f.Pos, f.Expr, what, fix)
}

// CheckFile reports the findings in one parsed file. The file must be
// parsed with object resolution on (the default) so constants and
// tabwriter-typed writers resolve. tables turns on the table-row rule.
func CheckFile(fset *token.FileSet, file *ast.File, tables bool) []Finding {
	var out []Finding
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		kind, fmtIdx := classify(call, tables)
		switch kind {
		case "":
			return true
		case "print":
			for _, arg := range call.Args {
				if tenantValued(arg) {
					out = append(out, Finding{fset.Position(arg.Pos()), exprString(fset, arg), "print", "log"})
				}
			}
			return true
		}
		if fmtIdx >= len(call.Args) {
			return true
		}
		format, ok := constString(call.Args[fmtIdx])
		if !ok {
			return true
		}
		if kind == "table?" {
			row := isRowFormat(format) || (fmtIdx == 1 && isTabwriter(call.Args[0]))
			if !row {
				return true
			}
			kind = "table"
		}
		args := call.Args[fmtIdx+1:]
		for _, u := range verbUses(format) {
			if u.arg >= len(args) || !strings.ContainsRune(unsafeVerbs, rune(u.verb)) {
				continue
			}
			arg := args[u.arg]
			if tenantValued(arg) {
				out = append(out, Finding{fset.Position(arg.Pos()), exprString(fset, arg), "%" + string(u.verb), kind})
			}
		}
		return true
	})
	return out
}

// notLoggers are receivers whose printf-style methods write something
// other than a log. fmt never gets here (classify handles it first, for the
// table rule), and fmt/status/errors Errorf is not a log method at all.
// t/tb/b are testing helpers in non-test support files.
var notLoggers = map[string]bool{
	"t": true, "tb": true, "b": true,
	// cobra's cmd.Printf writes command output to the user's own terminal,
	// not a log; CLI tables are covered by the table rule instead.
	"cmd": true,
}

var printfLogMethods = map[string]bool{
	"Printf": true, "Fatalf": true, "Panicf": true, "Infof": true,
	"Warnf": true, "Warningf": true, "Debugf": true, "Tracef": true, "Noticef": true,
}

var printLogFuncs = map[string]bool{
	"Print": true, "Println": true, "Fatal": true, "Fatalln": true, "Panic": true, "Panicln": true,
}

// classify returns the call kind ("log", "print", "table?" or "") and the
// index of its format argument.
func classify(call *ast.CallExpr, tables bool) (string, int) {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		// A local printf-style seam: logf(...), runCheckoutLogf(...).
		if strings.HasSuffix(strings.ToLower(fun.Name), "logf") {
			return "log", 0
		}
	case *ast.SelectorExpr:
		method := fun.Sel.Name
		recv := ""
		if id, ok := fun.X.(*ast.Ident); ok {
			recv = id.Name
		}
		switch {
		case recv == "log" && printLogFuncs[method]:
			return "print", 0
		case recv == "fmt":
			if tables && method == "Printf" {
				return "table?", 0
			}
			if tables && method == "Fprintf" {
				return "table?", 1
			}
		case notLoggers[recv]:
		case printfLogMethods[method], strings.HasSuffix(strings.ToLower(method), "logf"):
			return "log", 0
		case method == "Errorf" && strings.Contains(strings.ToLower(recv), "log"):
			// grpclog.Errorf, logger.Errorf; not fmt/status.Errorf.
			return "log", 0
		}
	}
	return "", 0
}

// tenantValued reports whether e's terminal name is in TenantFields.
func tenantValued(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		if x.Obj != nil && x.Obj.Kind == ast.Con {
			return false // a constant is not tenant input
		}
		return isTenantName(x.Name)
	case *ast.SelectorExpr:
		return isTenantName(x.Sel.Name)
	case *ast.CallExpr:
		// Proto getter: req.GetUsername().
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok && len(x.Args) == 0 &&
			len(sel.Sel.Name) > 3 && strings.HasPrefix(sel.Sel.Name, "Get") {
			return isTenantName(sel.Sel.Name[3:])
		}
		return false
	case *ast.ParenExpr:
		return tenantValued(x.X)
	case *ast.StarExpr:
		return tenantValued(x.X)
	case *ast.BinaryExpr:
		return x.Op == token.ADD && (tenantValued(x.X) || tenantValued(x.Y))
	}
	return false
}

func isTenantName(name string) bool {
	_, ok := TenantFields[strings.ToLower(name)]
	return ok
}

// isTabwriter reports whether w is an identifier declared in this file as
// tabwriter.NewWriter(...) or as a *tabwriter.Writer parameter or var.
func isTabwriter(w ast.Expr) bool {
	id, ok := w.(*ast.Ident)
	if !ok || id.Obj == nil {
		return false
	}
	switch d := id.Obj.Decl.(type) {
	case *ast.AssignStmt:
		for i, lhs := range d.Lhs {
			if l, ok := lhs.(*ast.Ident); ok && l.Name == id.Name && i < len(d.Rhs) {
				return isSelector(callFun(d.Rhs[i]), "tabwriter", "NewWriter")
			}
		}
	case *ast.ValueSpec:
		if d.Type != nil && isTabwriterType(d.Type) {
			return true
		}
		for i, n := range d.Names {
			if n.Name == id.Name && i < len(d.Values) {
				return isSelector(callFun(d.Values[i]), "tabwriter", "NewWriter")
			}
		}
	case *ast.Field:
		return isTabwriterType(d.Type)
	}
	return false
}

func isTabwriterType(t ast.Expr) bool {
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	return isSelector(t, "tabwriter", "Writer")
}

func callFun(e ast.Expr) ast.Expr {
	if c, ok := e.(*ast.CallExpr); ok {
		return c.Fun
	}
	return nil
}

func isSelector(e ast.Expr, pkg, name string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != name {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Name == pkg
}

// isRowFormat reports whether a fmt.Printf/Fprintf format prints a table
// row: a tab-separated cell (tabwriter) or a width-padded verb (%-25s).
func isRowFormat(format string) bool {
	if strings.Contains(format, "\t") {
		return true
	}
	for _, u := range verbUses(format) {
		if u.width {
			return true
		}
	}
	return false
}

// constString returns the value of a string literal or a "+" concatenation
// of string literals.
func constString(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		a, ok1 := constString(x.X)
		b, ok2 := constString(x.Y)
		return a + b, ok1 && ok2
	case *ast.ParenExpr:
		return constString(x.X)
	}
	return "", false
}

type verbUse struct {
	arg   int  // index into the arguments after the format
	verb  byte // 's', 'q', 'd', ...
	width bool // the verb has a width (%-25s, %10v)
	off   int  // byte offset of the verb letter in format
}

// verbUses maps each verb in format to the argument it consumes, following
// fmt's rules for '*' and explicit [n] indexes.
func verbUses(format string) []verbUse {
	var uses []verbUse
	arg := 0
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		if i < len(format) && format[i] == '%' {
			continue
		}
		width := false
		for i < len(format) {
			c := format[i]
			switch {
			case strings.IndexByte("+-# 0", c) >= 0:
				i++
			case c >= '1' && c <= '9':
				width = true
				for i < len(format) && format[i] >= '0' && format[i] <= '9' {
					i++
				}
			case c == '.':
				i++
				for i < len(format) && format[i] >= '0' && format[i] <= '9' {
					i++
				}
			case c == '*':
				arg++
				i++
			case c == '[':
				end := strings.IndexByte(format[i:], ']')
				if end < 0 {
					return uses
				}
				if n, err := strconv.Atoi(format[i+1 : i+end]); err == nil && n > 0 {
					arg = n - 1
				}
				i += end + 1
			default:
				goto verb
			}
		}
	verb:
		if i < len(format) {
			uses = append(uses, verbUse{arg: arg, verb: format[i], width: width, off: i})
			arg++
		}
	}
	return uses
}

func exprString(fset *token.FileSet, e ast.Expr) string {
	var b strings.Builder
	if err := printer.Fprint(&b, fset, e); err != nil {
		return fmt.Sprintf("<%T>", e)
	}
	return b.String()
}

// skipDirs are never scanned: generated, vendored, fixture or non-Go trees.
var skipDirs = map[string]bool{
	".git": true, "vendor": true, "third_party": true, "testdata": true,
	"node_modules": true, "web-ui": true,
}

// CheckTree parses every non-test .go file under root and returns the
// findings not covered by allow, sorted. allow is keyed by
// "<slash path relative to root>:<argument expression>". tableDir is the
// slash path (relative to root) whose files get the table-row rule.
// Returned unused holds allow keys that matched nothing, so a stale entry
// is noticed.
func CheckTree(root, tableDir string, allow map[string]string) (findings []Finding, scanned int, unused []string, err error) {
	used := map[string]bool{}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		scanned++
		tables := strings.HasPrefix(rel, tableDir+"/")
		for _, f := range CheckFile(fset, file, tables) {
			key := rel + ":" + f.Expr
			if _, ok := allow[key]; ok {
				used[key] = true
				continue
			}
			f.Pos.Filename = rel
			findings = append(findings, f)
		}
		return nil
	})
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i].Pos, findings[j].Pos
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		return a.Line < b.Line
	})
	for k := range allow {
		if !used[k] {
			unused = append(unused, k)
		}
	}
	sort.Strings(unused)
	return findings, scanned, unused, err
}
