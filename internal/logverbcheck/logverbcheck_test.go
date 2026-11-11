package logverbcheck

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// check parses body as the inside of a function in a file that imports
// the packages the fixtures use, and returns "<expr> <verb> <kind>" per
// finding.
func check(t *testing.T, decls, body string, tables bool) []string {
	t.Helper()
	src := "package p\n\n" + decls + "\nfunc f() {\n" + body + "\n}\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parse fixture: %v\n%s", err, src)
	}
	var got []string
	for _, f := range CheckFile(fset, file, tables) {
		got = append(got, f.Expr+" "+f.Verb+" "+f.Kind)
	}
	return got
}

// The sample from the issue's acceptance criteria.
func TestCheckFile_IssueSample(t *testing.T) {
	src := "package p\n\nfunc f() {\n\tlog.Printf(\"%s\", req.Username)\n}\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sample.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := CheckFile(fset, file, false)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(got), got)
	}
	want := "sample.go:4:19: tenant-controlled req.Username logged with %s; use %q (#3457)"
	if got[0].String() != want {
		t.Fatalf("message:\n got %s\nwant %s", got[0], want)
	}
}

// Every field class the issue and the two log slices (#3468, #3473) named
// must be caught. The names are spelled out here rather than read from
// TenantFields, so dropping an entry from the table fails this test.
func TestCheckFile_FlagsEveryTenantField(t *testing.T) {
	fields := []string{
		// issue #3457: box/container name, username, label key/value,
		// project, process name, SSH login, model name
		"req.ContainerName", "containerName", "box", "boxName", "c.Container", "v.TargetContainer",
		"req.Username", "username", "user",
		"labelKey", "labelValue",
		"req.Project", "projectName",
		"ex.Comm", "processName",
		"sshUser", "sshLogin", "loginUser",
		"model", "req.ModelName", "modelID",
		// #3468 / #3473 classifications
		"c.Owner", "accountName", "box.ReleasedBy", "claims.KeyOwner", "ev.Tenant",
		"r.FullDomain", "subdomain", "appName", "skill", "req.SkillId", "spotID",
	}
	for _, f := range fields {
		got := check(t, "", `log.Printf("x %s", `+f+`)`, false)
		if want := []string{f + " %s log"}; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", f, got, want)
		}
	}
	if len(fields) < len(TenantFields) {
		t.Errorf("TenantFields has %d entries but only %d are exercised; add the new one here", len(TenantFields), len(fields))
	}
}

func TestCheckFile_Flagged(t *testing.T) {
	cases := []struct {
		name, decls, body string
		tables            bool
		want              []string
	}{
		{"v verb", "", `log.Printf("%v", username)`, false, []string{"username %v log"}},
		{"Fatalf", "", `log.Fatalf("%s: %v", username, err)`, false, []string{"username %s log"}},
		{"Panicf", "", `log.Panicf("%s", username)`, false, []string{"username %s log"}},
		{"padded verb", "", `log.Printf("%-20s|", username)`, false, []string{"username %s log"}},
		{"second arg", "", `log.Printf("%d %s", n, req.Username)`, false, []string{"req.Username %s log"}},
		{"star width", "", `log.Printf("%*d %s", w, n, username)`, false, []string{"username %s log"}},
		{"explicit index", "", `log.Printf("%[2]s %[1]d", n, username)`, false, []string{"username %s log"}},
		{"concatenated format", "", `log.Printf("a " + "%s", username)`, false, []string{"username %s log"}},
		{"proto getter", "", `log.Printf("%s", req.GetUsername())`, false, []string{"req.GetUsername() %s log"}},
		{"concatenated value", "", `log.Printf("%s", username + "-container")`, false, []string{`username + "-container" %s log`}},
		{"parenthesised", "", `log.Printf("%s", (username))`, false, []string{"(username) %s log"}},
		{"pointer", "", `log.Printf("%s", *tenant)`, false, []string{"*tenant %s log"}},
		{"logger Printf", "", `s.logger.Printf("%s", username)`, false, []string{"username %s log"}},
		{"logf seam", "", `s.logf("%s", username)`, false, []string{"username %s log"}},
		{"Logf seam", "", `cfg.Logf("%s", username)`, false, []string{"username %s log"}},
		{"func-value seam", "", `runCheckoutLogf("%s", box)`, false, []string{"box %s log"}},
		{"Infof", "", `logger.Infof("%s", username)`, false, []string{"username %s log"}},
		{"Warningf", "", `grpclog.Warningf("%s", username)`, false, []string{"username %s log"}},
		{"grpclog Errorf", "", `grpclog.Errorf("%s", username)`, false, []string{"username %s log"}},
		{"Println", "", `log.Println("stopped", username)`, false, []string{"username print log"}},
		{"Print", "", `log.Print(req.Username)`, false, []string{"req.Username print log"}},
		{"Fatal", "", `log.Fatal(username)`, false, []string{"username print log"}},
		{"table tab row", "", `fmt.Printf("%s\t%d\n", c.ContainerName, n)`, true, []string{"c.ContainerName %s table"}},
		{"table padded row", "", `fmt.Printf("%-25s %s\n", c.ContainerName, ip)`, true, []string{"c.ContainerName %s table"}},
		{"table Fprintf row", "", `fmt.Fprintf(os.Stdout, "%-20s %v\n", ip, p.Tenant)`, true, []string{"p.Tenant %v table"}},
		{"tabwriter writer", "", "w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)\nfmt.Fprintf(w, \"%s\\n\", username)", true, []string{"username %s table"}},
		{"tabwriter var", "", "var w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)\nfmt.Fprintf(w, \"%s\\n\", username)", true, []string{"username %s table"}},
		{"tabwriter param", "func g(w *tabwriter.Writer) { fmt.Fprintf(w, \"%s\\n\", username) }", ``, true, []string{"username %s table"}},
		{"log rule in table dir", "", `log.Printf("%s", username)`, true, []string{"username %s log"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := check(t, tc.decls, tc.body, tc.tables)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCheckFile_NotFlagged(t *testing.T) {
	cases := []struct {
		name, decls, body string
		tables            bool
	}{
		{"q verb", "", `log.Printf("%q %-20q", username, req.Username)`, false},
		{"int verb", "", `log.Printf("%d %x", user, box)`, false},
		{"string literal", "", `log.Printf("%s", "username")`, false},
		{"file constant", `const user = "root"`, `log.Printf("%s", user)`, false},
		{"local constant", "", "const box = \"probe\"\nlog.Printf(\"%s\", box)", false},
		{"wrapped in escape helper", "", `fmt.Printf("%-25s %s\n", escapeControl(c.ContainerName), ip)`, true},
		{"wrapped in strconv.Quote", "", `log.Printf("%s", strconv.Quote(username))`, false},
		{"len of value", "", `log.Printf("%v", len(username))`, false},
		{"getter with args", "", `log.Printf("%s", req.GetUser(ctx))`, false},
		{"generic name", "", `log.Printf("%s %s %s", req.Name, id, key)`, false},
		{"explicit index to other arg", "", `log.Printf("%[1]s %[2]q", ip, username)`, false},
		{"escaped percent", "", `log.Printf("100%%s %q", username)`, false},
		{"verb with no arg", "", `log.Printf("%s %s", ip)`, false},
		{"fmt.Errorf out of scope (#3472)", "", `_ = fmt.Errorf("box %s: %w", username, err)`, false},
		{"status.Errorf out of scope", "", `_ = status.Errorf(codes.NotFound, "%s", username)`, false},
		{"errors receiver", "", `_ = errors.Errorf("%s", username)`, false},
		{"non-log Errorf", "", `x.Errorf("%s", username)`, false},
		{"testing helper", "", `t.Fatalf("%s", username)`, false},
		{"cobra output", "", `cmd.Printf("tearing down %s\n", box)`, false},
		{"Sprintf", "", `_ = fmt.Sprintf("%s", username)`, false},
		{"non-row fmt.Printf in table dir", "", `fmt.Printf("created %s\n", username)`, true},
		{"row outside table dir", "", `fmt.Printf("%-25s %s\n", c.ContainerName, ip)`, false},
		{"Fprintf to non-tabwriter", "", "var b strings.Builder\nfmt.Fprintf(&b, \"%s\\n\", username)", true},
		{"tabwriter header only", "", "w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)\nfmt.Fprintf(w, \"NAME\\tSTATE\\n\")", true},
		{"non-constant format", "", `log.Printf(format, username)`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check(t, tc.decls, tc.body, tc.tables); len(got) != 0 {
				t.Errorf("got %v, want no findings", got)
			}
		})
	}
}

func TestVerbUses(t *testing.T) {
	cases := []struct {
		format string
		want   []verbUse
	}{
		{"%s", []verbUse{{arg: 0, verb: 's', off: 1}}},
		{"a %d %-5s", []verbUse{{0, 'd', false, 3}, {1, 's', true, 8}}},
		{"%*d %s", []verbUse{{1, 'd', false, 2}, {2, 's', false, 5}}},
		{"%[2]s %[1]q %v", []verbUse{{1, 's', false, 4}, {0, 'q', false, 10}, {1, 'v', false, 13}}},
		{"%%s %.3f", []verbUse{{0, 'f', false, 7}}},
	}
	for _, tc := range cases {
		if got := verbUses(tc.format); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("verbUses(%q) = %+v, want %+v", tc.format, got, tc.want)
		}
	}
}

// CheckTree: the table rule applies only under tableDir, test files and
// skipped directories are not scanned, the allowlist suppresses exactly
// its key, and an unused key is reported.
func TestCheckTree(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("package p\n\nfunc f() {\n"+body+"\n}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a/log.go", `log.Printf("%s %s", username, box)`)
	write("a/log_test.go", `log.Printf("%s", username)`)
	write("a/testdata/x.go", `log.Printf("%s", username)`)
	write("vendor/v/x.go", `log.Printf("%s", username)`)
	write("internal/cmd/table.go", `fmt.Printf("%-20s\n", username)`)
	write("other/table.go", `fmt.Printf("%-20s\n", username)`)

	allow := map[string]string{"a/log.go:box": "fixture", "a/log.go:gone": "stale"}
	findings, scanned, unused, err := CheckTree(root, "internal/cmd", allow)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range findings {
		got = append(got, f.Pos.Filename+" "+f.Expr+" "+f.Kind)
	}
	want := []string{"a/log.go username log", "internal/cmd/table.go username table"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %v, want %v", got, want)
	}
	if scanned != 3 {
		t.Errorf("scanned %d files, want 3", scanned)
	}
	if !reflect.DeepEqual(unused, []string{"a/log.go:gone"}) {
		t.Errorf("unused = %v", unused)
	}
	if len(findings) > 0 && !strings.HasPrefix(findings[0].String(), "a/log.go:4:") {
		t.Errorf("position not relative to root: %s", findings[0])
	}
}
