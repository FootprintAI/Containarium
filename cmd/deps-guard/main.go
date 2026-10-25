// Command deps-guard is the CI half of the dependency-change gate (#2794).
// It is a CI tool, not a shipped binary; scripts/ci/deps-guard.sh drives it.
//
//	deps-guard env
//	    Fail unless `go env` pins -mod=readonly and GOSUMDB=sum.golang.org and
//	    sets none of GONOSUMDB, GOPRIVATE, GONOPROXY, GOINSECURE.
//	deps-guard layout < files
//	    Fail if the tracked file list (NUL- or newline-separated, e.g.
//	    `git ls-files -z`) holds a second go.mod, a go.work or a vendor/
//	    directory: places this gate does not read.
//	deps-guard diff -base base.go.mod -head go.mod -gosum go.sum [-report out.md]
//	    Fail on a new/changed replace, or a new/changed module that the
//	    checksum database does not know or disagrees with. -report writes the
//	    Markdown report (also on failure).
//
// Exit status: 0 pass, 1 policy failure, 2 the verdict could not be reached.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/depsguard"
)

const (
	exitPass  = 0
	exitFail  = 1
	exitError = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: deps-guard env | deps-guard layout < files | deps-guard diff -base F -head F -gosum F [-report F]")
		return exitError
	}
	switch args[0] {
	case "env":
		return runEnv(ctx, stdout, stderr)
	case "diff":
		return runDiff(ctx, args[1:], stdout, stderr)
	case "layout":
		return runLayout(os.Stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "deps-guard: unknown subcommand %q\n", args[0])
		return exitError
	}
}

// escapeData applies GitHub's workflow-command data encoding (% CR LF), the
// same as @actions/core, so an annotation message is always one command.
func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

// report prints each finding as a log line and, on GitHub Actions, as an
// annotation. Both carry PR-controlled text (a quoted replace target in
// go.mod can hold a newline followed by "::warning ..."), so both go
// through Finding.String, which escapes every control character, and the
// annotation message is escaped once more with the runner's own encoding.
// The annotation title holds only the rule name, which is fixed here.
func report(stderr io.Writer, findings []depsguard.Finding) {
	for _, f := range findings {
		line := f.String()
		fmt.Fprintln(stderr, "FAIL "+line)
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			fmt.Fprintf(stderr, "::error file=go.mod,title=deps-guard %s::%s\n", f.Kind, escapeData(line))
		}
	}
}

// fail prints an error that may quote PR content (go mod edit echoes parse
// errors from go.mod) on one escaped line.
func fail(stderr io.Writer, prefix string, err error) {
	fmt.Fprintln(stderr, prefix+depsguard.LogSafe(err.Error()))
}

func runEnv(ctx context.Context, stdout, stderr io.Writer) int {
	args := append([]string{"env", "-json"}, depsguard.GoEnvVars...)
	// #nosec G204 -- fixed binary, no shell; the arguments are constant variable names.
	out, err := exec.CommandContext(ctx, "go", args...).Output()
	if err != nil {
		fail(stderr, "deps-guard: go env: ", err)
		return exitError
	}
	var env depsguard.GoEnv
	if err := json.Unmarshal(out, &env); err != nil {
		fail(stderr, "deps-guard: decode go env: ", err)
		return exitError
	}
	if f := depsguard.CheckEnv(env); len(f) > 0 {
		report(stderr, f)
		return exitFail
	}
	fmt.Fprintf(stdout, "go env ok: GOFLAGS=%q GOSUMDB=%q, no checksum-database exemptions\n", env.GOFLAGS, env.GOSUMDB)
	return exitPass
}

func runLayout(stdin io.Reader, stdout, stderr io.Writer) int {
	b, err := io.ReadAll(stdin)
	if err != nil {
		fail(stderr, "deps-guard layout: ", err)
		return exitError
	}
	sep := "\n"
	if strings.Contains(string(b), "\x00") {
		sep = "\x00"
	}
	var files []string
	for _, f := range strings.Split(string(b), sep) {
		if f != "" {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		fmt.Fprintln(stderr, "deps-guard layout: empty file list")
		return exitError
	}
	if f := depsguard.CheckLayout(files); len(f) > 0 {
		report(stderr, f)
		return exitFail
	}
	fmt.Fprintf(stdout, "layout ok: one go.mod at the root, no go.work, no vendor/ (%d files)\n", len(files))
	return exitPass
}

func runDiff(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	basePath := fs.String("base", "", "go.mod at the PR base (missing file: empty)")
	headPath := fs.String("head", "go.mod", "go.mod at the PR head")
	sumPath := fs.String("gosum", "go.sum", "go.sum at the PR head")
	reportPath := fs.String("report", "", "write the Markdown report here")
	sumdbURL := fs.String("sumdb", depsguard.DefaultSumDB, "checksum database base URL")
	proxyURL := fs.String("proxy", depsguard.DefaultProxy, "module proxy base URL (age and source only)")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *basePath == "" {
		fmt.Fprintln(stderr, "deps-guard diff: -base is required")
		return exitError
	}
	base, err := depsguard.LoadGoMod(ctx, *basePath)
	if err != nil {
		fail(stderr, "deps-guard: ", err)
		return exitError
	}
	head, err := depsguard.LoadGoMod(ctx, *headPath)
	if err != nil {
		fail(stderr, "deps-guard: ", err)
		return exitError
	}
	sumBytes, err := os.ReadFile(*sumPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fail(stderr, "deps-guard: ", err)
		return exitError
	}
	sum, err := depsguard.ParseGoSum(sumBytes)
	if err != nil {
		fail(stderr, "deps-guard: ", err)
		return exitError
	}
	client := &http.Client{Timeout: 30 * time.Second}
	checker := depsguard.Checker{
		SumDB: depsguard.HTTPSumDB{BaseURL: *sumdbURL, Client: client},
		Proxy: depsguard.HTTPProxy{BaseURL: *proxyURL, Client: client},
	}
	rep, err := checker.Check(ctx, base, head, sum)
	if err != nil {
		fail(stderr, "deps-guard: no verdict: ", err)
		return exitError
	}
	md := depsguard.RenderMarkdown(rep)
	if *reportPath != "" {
		// #nosec G703 -- the path is the CI caller's own -report flag, not PR data.
		if err := os.WriteFile(*reportPath, []byte(md), 0o600); err != nil {
			fail(stderr, "deps-guard: ", err)
			return exitError
		}
	}
	if rep.Failed() {
		report(stderr, rep.Findings)
		return exitFail
	}
	fmt.Fprintf(stdout, "deps-guard ok: %d new or changed module(s), no new or changed replace\n", len(rep.Modules))
	return exitPass
}
