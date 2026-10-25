package depsguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// fakeSumDB serves /lookup/<escaped path>@<escaped version> the way
// sum.golang.org does: a tree-id line, the two hash lines, then a signed note
// we do not verify. Anything not listed is a 404, as for a module the
// checksum database has never seen.
func fakeSumDB(t *testing.T, records map[string]SumRecord) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/lookup/")
		at := strings.LastIndex(key, "@")
		if at < 0 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		path, version := key[:at], key[at+1:]
		rec, ok := records[path+"@"+version]
		if !ok {
			http.Error(w, "not found: "+key, http.StatusNotFound)
			return
		}
		unescaped := unescapeForTest(path)
		v := unescapeForTest(version)
		_, _ = w.Write([]byte("1234\n" +
			unescaped + " " + v + " " + rec.Hash + "\n" +
			unescaped + " " + v + "/go.mod " + rec.GoModHash + "\n\ngo.sum database tree\n"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func unescapeForTest(s string) string {
	var b strings.Builder
	bang := false
	for _, r := range s {
		if r == '!' {
			bang = true
			continue
		}
		if bang {
			r = r - 'a' + 'A'
			bang = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

type fakeInfo struct {
	time   string
	origin string
}

func fakeProxy(t *testing.T, infos map[string]fakeInfo) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /<escaped path>/@v/<escaped version>.info
		p := strings.TrimPrefix(r.URL.Path, "/")
		i := strings.Index(p, "/@v/")
		if i < 0 || !strings.HasSuffix(p, ".info") {
			http.NotFound(w, r)
			return
		}
		key := p[:i] + "@" + strings.TrimSuffix(p[i+4:], ".info")
		info, ok := infos[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		body := `{"Version":"x","Time":"` + info.time + `"`
		if info.origin != "" {
			body += `,"Origin":{"VCS":"git","URL":"` + info.origin + `"}`
		}
		_, _ = w.Write([]byte(body + "}"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The hashes are the real sum.golang.org records for these versions, so the
// same fixtures also pass or fail the same way against the live service
// (scripts/ci/deps-guard.sh --self-test).
var realRecords = map[string]SumRecord{
	"gopkg.in/yaml.v3@v3.0.1": {
		Hash:      "h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=",
		GoModHash: "h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=",
	},
	"golang.org/x/text@v0.3.8": {
		Hash:      "h1:nAL+RVCQ9uMn3vJZbV+MRnydTJFPf8qqY42YiA6MrqY=",
		GoModHash: "h1:E6s5w1FMmriuDzIBO73fBruAKo1PCIq6d2Q6DHfQ8WQ=",
	},
}

var fixedNow = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func newChecker(t *testing.T) Checker {
	t.Helper()
	sum := fakeSumDB(t, realRecords)
	proxy := fakeProxy(t, map[string]fakeInfo{
		"gopkg.in/yaml.v3@v3.0.1": {time: "2022-05-27T08:35:30Z"},
	})
	return Checker{
		SumDB: HTTPSumDB{BaseURL: sum.URL, Client: sum.Client()},
		Proxy: HTTPProxy{BaseURL: proxy.URL, Client: proxy.Client()},
		Now:   func() time.Time { return fixedNow },
	}
}

func loadFixture(t *testing.T, dir string) (GoMod, GoMod, GoSum, string) {
	t.Helper()
	base, err := LoadGoMod(context.Background(), filepath.Join(dir, "base.go.mod"))
	if err != nil {
		t.Fatalf("load base: %v", err)
	}
	head, err := LoadGoMod(context.Background(), filepath.Join(dir, "head.go.mod"))
	if err != nil {
		t.Fatalf("load head: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "head.go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	sum, err := ParseGoSum(b)
	if err != nil {
		t.Fatal(err)
	}
	expect, err := os.ReadFile(filepath.Join(dir, "expect"))
	if err != nil {
		t.Fatal(err)
	}
	return base, head, sum, strings.TrimSpace(string(expect))
}

// One fixture per failure, plus the passing one. Every fixture directory is
// exercised, and the set must contain at least one pass and one fail, so a
// deleted fixture or a guard that never fails cannot leave this green.
func TestFixtures(t *testing.T) {
	dirs, err := filepath.Glob("testdata/*")
	if err != nil {
		t.Fatal(err)
	}
	var sawPass, sawFail bool
	for _, dir := range dirs {
		dir := dir
		t.Run(filepath.Base(dir), func(t *testing.T) {
			base, head, sum, expect := loadFixture(t, dir)
			rep, err := newChecker(t).Check(context.Background(), base, head, sum)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			var kinds []string
			for _, f := range rep.Findings {
				kinds = append(kinds, string(f.Kind))
			}
			sort.Strings(kinds)
			if expect == "pass" {
				sawPass = true
				if len(kinds) != 0 {
					t.Fatalf("want no findings, got %v", rep.Findings)
				}
				return
			}
			sawFail = true
			if len(kinds) != 1 || kinds[0] != expect {
				t.Fatalf("want exactly one %q finding, got %v", expect, rep.Findings)
			}
		})
	}
	if !sawPass || !sawFail {
		t.Fatalf("fixture set must hold a passing and a failing case (pass=%v fail=%v)", sawPass, sawFail)
	}
}

func TestReplaceRules(t *testing.T) {
	grpc := Replace{Old: ModuleVersion{Path: "google.golang.org/grpc"}, New: ModuleVersion{Path: "google.golang.org/grpc", Version: "v1.83.2"}}
	tests := []struct {
		name       string
		base, head []Replace
		want       []FindingKind
	}{
		{"unchanged existing replace passes", []Replace{grpc}, []Replace{grpc}, nil},
		{"removed replace passes", []Replace{grpc}, nil, nil},
		{"new replace fails", nil, []Replace{grpc}, []FindingKind{FindingReplaceAdded}},
		{"retargeted version fails", []Replace{grpc}, []Replace{{Old: grpc.Old, New: ModuleVersion{Path: grpc.New.Path, Version: "v1.83.1"}}}, []FindingKind{FindingReplaceChanged}},
		{"old version narrowed is a new directive", []Replace{grpc}, []Replace{{Old: ModuleVersion{Path: grpc.Old.Path, Version: "v1.84.0"}, New: grpc.New}}, []FindingKind{FindingReplaceAdded}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckReplaces(GoMod{Replace: tc.base}, GoMod{Replace: tc.head})
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want kinds %v", got, tc.want)
			}
			for i := range got {
				if got[i].Kind != tc.want[i] {
					t.Fatalf("got %v, want kinds %v", got, tc.want)
				}
			}
		})
	}
}

func TestCheckEnv(t *testing.T) {
	good := GoEnv{GOFLAGS: "-mod=readonly", GOSUMDB: "sum.golang.org"}
	tests := []struct {
		name string
		env  GoEnv
		bad  bool
	}{
		{"pinned env passes", good, false},
		{"readonly among other flags passes", GoEnv{GOFLAGS: "-trimpath -mod=readonly", GOSUMDB: "sum.golang.org"}, false},
		{"GOFLAGS without readonly fails", GoEnv{GOFLAGS: "-mod=mod", GOSUMDB: "sum.golang.org"}, true},
		{"empty GOFLAGS fails", GoEnv{GOSUMDB: "sum.golang.org"}, true},
		{"GOSUMDB off fails", GoEnv{GOFLAGS: "-mod=readonly", GOSUMDB: "off"}, true},
		{"other GOSUMDB fails", GoEnv{GOFLAGS: "-mod=readonly", GOSUMDB: "sum.example.com"}, true},
		{"GONOSUMDB set fails", GoEnv{GOFLAGS: "-mod=readonly", GOSUMDB: "sum.golang.org", GONOSUMDB: "example.com"}, true},
		{"GOPRIVATE set fails", GoEnv{GOFLAGS: "-mod=readonly", GOSUMDB: "sum.golang.org", GOPRIVATE: "example.com/*"}, true},
		{"GONOPROXY set fails", GoEnv{GOFLAGS: "-mod=readonly", GOSUMDB: "sum.golang.org", GONOPROXY: "example.com"}, true},
		{"GOINSECURE set fails", GoEnv{GOFLAGS: "-mod=readonly", GOSUMDB: "sum.golang.org", GOINSECURE: "example.com"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckEnv(tc.env)
			if (len(got) > 0) != tc.bad {
				t.Fatalf("CheckEnv(%+v) = %v, want bad=%v", tc.env, got, tc.bad)
			}
			for _, f := range got {
				if f.Kind != FindingUnsafeEnv {
					t.Fatalf("unexpected kind %q", f.Kind)
				}
			}
		})
	}
}

func TestEscapePath(t *testing.T) {
	for in, want := range map[string]string{
		"github.com/BurntSushi/toml": "github.com/!burnt!sushi/toml",
		"gopkg.in/yaml.v3":           "gopkg.in/yaml.v3",
		"v1.0.0-RC1":                 "v1.0.0-!r!c1",
	} {
		if got := EscapePath(in); got != want {
			t.Errorf("EscapePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// A sumdb outage must be an error (exit 2 in the CLI), never read as
// "absent" (a policy failure) or as "present" (a silent pass).
func TestSumDBServerErrorIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()
	_, found, err := HTTPSumDB{BaseURL: srv.URL, Client: srv.Client(), Attempts: 1}.Lookup(context.Background(), "gopkg.in/yaml.v3", "v3.0.1")
	if err == nil || found {
		t.Fatalf("want error, got found=%v err=%v", found, err)
	}
}

func TestReportAgeAndSource(t *testing.T) {
	sum := fakeSumDB(t, map[string]SumRecord{
		"example.com/young@v0.1.0":       {Hash: "h1:y", GoModHash: "h1:ym"},
		"example.com/old@v1.2.0":         {Hash: "h1:o", GoModHash: "h1:om"},
		"example.com/!upper!case@v1.0.0": {Hash: "h1:u", GoModHash: "h1:um"},
		"example.com/bumped@v1.1.0":      {Hash: "h1:b", GoModHash: "h1:bm"},
	})
	proxy := fakeProxy(t, map[string]fakeInfo{
		"example.com/young@v0.1.0":       {time: fixedNow.Add(-13 * 24 * time.Hour).Format(time.RFC3339), origin: "https://git.example.com/young"},
		"example.com/old@v1.2.0":         {time: fixedNow.Add(-400 * 24 * time.Hour).Format(time.RFC3339)},
		"example.com/!upper!case@v1.0.0": {time: fixedNow.Add(-15 * 24 * time.Hour).Format(time.RFC3339)},
		"example.com/bumped@v1.1.0":      {time: fixedNow.Add(-2 * 24 * time.Hour).Format(time.RFC3339)},
	})
	c := Checker{
		SumDB: HTTPSumDB{BaseURL: sum.URL, Client: sum.Client()},
		Proxy: HTTPProxy{BaseURL: proxy.URL, Client: proxy.Client()},
		Now:   func() time.Time { return fixedNow },
	}
	base := GoMod{Require: []Require{{Path: "example.com/bumped", Version: "v1.0.0"}}}
	head := GoMod{Require: []Require{
		{Path: "example.com/young", Version: "v0.1.0"},
		{Path: "example.com/old", Version: "v1.2.0", Indirect: true},
		{Path: "example.com/UpperCase", Version: "v1.0.0"},
		{Path: "example.com/bumped", Version: "v1.1.0"},
		{Path: "example.com/noinfo", Version: "v1.0.0"},
	}}
	// noinfo is deliberately absent from the fake sumdb: it must fail and
	// still be listed, with an unknown (so bold) age.
	rep, err := c.Check(context.Background(), base, head, GoSum{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Kind != FindingNotInSumDB || rep.Findings[0].Module != "example.com/noinfo@v1.0.0" {
		t.Fatalf("findings = %v", rep.Findings)
	}
	md := RenderMarkdown(rep)
	for _, want := range []string{
		Marker,
		"| **`example.com/young`** | **added** | **`v0.1.0`** | **13 days** | **`https://git.example.com/young`** |",
		"| `example.com/old` | added (indirect) | `v1.2.0` | 400 days | proxy.golang.org (no VCS origin recorded) |",
		"| `example.com/UpperCase` | added | `v1.0.0` | 15 days |",
		"| **`example.com/noinfo`** | **added** | **`v1.0.0`** | **unknown** | **unknown** |",
		"not-in-sumdb",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("report missing %q\n---\n%s", want, md)
		}
	}
	// A version bump is not a new module; it is listed separately with its age.
	if !strings.Contains(md, "| **`example.com/bumped`** | **`v1.0.0` → `v1.1.0`** | **2 days** |") {
		t.Errorf("report missing the bumped module row\n---\n%s", md)
	}
}

// stripCodeSpans removes CommonMark code spans: a run of N backticks opens
// one, and the next run of exactly N closes it. What is left is the text a
// renderer would interpret as Markdown or HTML.
func stripCodeSpans(s string) string {
	var out strings.Builder
	run := func(i int) int {
		j := i
		for j < len(s) && s[j] == '`' {
			j++
		}
		return j - i
	}
	for i := 0; i < len(s); {
		if s[i] != '`' {
			out.WriteByte(s[i])
			i++
			continue
		}
		n := run(i)
		closed := -1
		for j := i + n; j < len(s); {
			if s[j] == '`' {
				m := run(j)
				if m == n {
					closed = j
					break
				}
				j += m
				continue
			}
			j++
		}
		if closed < 0 {
			out.WriteString(s[i : i+n]) // unmatched: literal backticks
			i += n
			continue
		}
		i = closed + n
	}
	return out.String()
}

// PR-controlled text (a quoted local replace target can hold anything) and
// proxy-supplied text (a module's VCS origin URL) must reach the sticky
// comment only inside code spans, where links, mentions and HTML are inert,
// and must not break the table row.
func TestRenderNeutralisesHostileText(t *testing.T) {
	base, head, sum, _ := loadFixture(t, "testdata/fail-replace-hostile-text")
	hostileOrigin := "https://evil.example/@someone [x](https://evil.example) <b>"
	proxy := fakeProxy(t, map[string]fakeInfo{
		"example.com/new@v1.0.0": {time: "2020-01-01T00:00:00Z", origin: hostileOrigin},
	})
	sumdb := fakeSumDB(t, map[string]SumRecord{"example.com/new@v1.0.0": {Hash: "h1:n", GoModHash: "h1:nm"}})
	head.Require = append(head.Require, Require{Path: "example.com/new", Version: "v1.0.0"})
	c := Checker{
		SumDB: HTTPSumDB{BaseURL: sumdb.URL, Client: sumdb.Client()},
		Proxy: HTTPProxy{BaseURL: proxy.URL, Client: proxy.Client()},
		Now:   func() time.Time { return fixedNow },
	}
	rep, err := c.Check(context.Background(), base, head, sum)
	if err != nil {
		t.Fatal(err)
	}
	md := RenderMarkdown(rep)
	body := strings.TrimPrefix(md, Marker+"\n")
	if body == md {
		t.Fatalf("report does not start with the marker:\n%s", md)
	}
	bare := stripCodeSpans(body)
	for _, bad := range []string{"@someone", "](", "<img", "<b>", "-->", "::warning"} {
		if strings.Contains(bare, bad) {
			t.Errorf("%q reaches the comment outside a code span:\n%s", bad, md)
		}
	}
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "::") {
			t.Errorf("a report line starts a workflow command: %q", line)
		}
		if strings.HasPrefix(line, "| replace-added") && strings.Count(strings.ReplaceAll(line, `\|`, ""), "|") != 4 {
			t.Errorf("hostile text breaks the table row: %q", line)
		}
	}
	if !strings.Contains(md, "evil.example") {
		t.Errorf("the hostile text should still be shown, as code:\n%s", md)
	}
}

func TestParseGoSumConflicts(t *testing.T) {
	sum, err := ParseGoSum([]byte("m v1 h1:a\nm v1 h1:a\nm v1/go.mod h1:b\nn v2 h1:c\nn v2 h1:d\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Conflicts) != 1 || sum.Conflicts[0] != "n v2" {
		t.Fatalf("conflicts = %v, want [n v2] (an identical duplicate is not a conflict)", sum.Conflicts)
	}
	rep, err := Checker{SumDB: HTTPSumDB{}, Proxy: HTTPProxy{}}.Check(context.Background(), GoMod{}, GoMod{}, sum)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Kind != FindingSumConflict {
		t.Fatalf("findings = %v", rep.Findings)
	}
}

func TestCheckLayout(t *testing.T) {
	tests := []struct {
		files []string
		bad   []string
	}{
		{[]string{"go.mod", "go.sum", "internal/depsguard/testdata/pass/head.go.mod", "cmd/x/main.go"}, nil},
		{[]string{"go.mod", "tools/go.mod"}, []string{"tools/go.mod"}},
		{[]string{"go.mod", "go.work"}, []string{"go.work"}},
		{[]string{"go.mod", "go.work.sum"}, []string{"go.work.sum"}},
		{[]string{"go.mod", "vendor/modules.txt"}, []string{"vendor/modules.txt"}},
		{[]string{"go.mod", "sub/vendor/modules.txt", "web/vendor/lib.js"}, []string{"sub/vendor/modules.txt"}},
	}
	for _, tc := range tests {
		got := CheckLayout(tc.files)
		var mods []string
		for _, f := range got {
			if f.Kind != FindingLayout {
				t.Fatalf("kind %q", f.Kind)
			}
			mods = append(mods, f.Module)
		}
		if strings.Join(mods, ",") != strings.Join(tc.bad, ",") {
			t.Errorf("CheckLayout(%v) flagged %v, want %v", tc.files, mods, tc.bad)
		}
	}
}
