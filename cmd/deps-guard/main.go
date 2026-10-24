// Command deps-guard is the CI half of the dependency-change gate (#2794).
// It is a CI tool, not a shipped binary; scripts/ci/deps-guard.sh drives it.
//
//	deps-guard env
//	    Fail unless `go env` pins -mod=readonly and GOSUMDB=sum.golang.org and
//	    sets none of GONOSUMDB, GOPRIVATE, GONOPROXY, GOINSECURE.
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
		fmt.Fprintln(stderr, "usage: deps-guard env | deps-guard diff -base F -head F -gosum F [-report F]")
		return exitError
	}
	switch args[0] {
	case "env":
		return runEnv(ctx, stdout, stderr)
	case "diff":
		return runDiff(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "deps-guard: unknown subcommand %q\n", args[0])
		return exitError
	}
}

func report(stderr io.Writer, findings []depsguard.Finding) {
	for _, f := range findings {
		fmt.Fprintln(stderr, "FAIL "+f.String())
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			// Annotation; the module path and detail come from go.mod, which
			// the go parser has already constrained to safe characters.
			fmt.Fprintf(stderr, "::error file=go.mod,title=deps-guard %s::%s\n", f.Kind, f.Detail)
		}
	}
}

func runEnv(ctx context.Context, stdout, stderr io.Writer) int {
	args := append([]string{"env", "-json"}, depsguard.GoEnvVars...)
	// #nosec G204 -- fixed binary, no shell; the arguments are constant variable names.
	out, err := exec.CommandContext(ctx, "go", args...).Output()
	if err != nil {
		fmt.Fprintf(stderr, "deps-guard: go env: %v\n", err)
		return exitError
	}
	var env depsguard.GoEnv
	if err := json.Unmarshal(out, &env); err != nil {
		fmt.Fprintf(stderr, "deps-guard: decode go env: %v\n", err)
		return exitError
	}
	if f := depsguard.CheckEnv(env); len(f) > 0 {
		report(stderr, f)
		return exitFail
	}
	fmt.Fprintf(stdout, "go env ok: GOFLAGS=%q GOSUMDB=%q, no checksum-database exemptions\n", env.GOFLAGS, env.GOSUMDB)
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
		fmt.Fprintln(stderr, "deps-guard:", err)
		return exitError
	}
	head, err := depsguard.LoadGoMod(ctx, *headPath)
	if err != nil {
		fmt.Fprintln(stderr, "deps-guard:", err)
		return exitError
	}
	sumBytes, err := os.ReadFile(*sumPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, "deps-guard:", err)
		return exitError
	}
	sum, err := depsguard.ParseGoSum(sumBytes)
	if err != nil {
		fmt.Fprintln(stderr, "deps-guard:", err)
		return exitError
	}
	client := &http.Client{Timeout: 30 * time.Second}
	checker := depsguard.Checker{
		SumDB: depsguard.HTTPSumDB{BaseURL: *sumdbURL, Client: client},
		Proxy: depsguard.HTTPProxy{BaseURL: *proxyURL, Client: client},
	}
	rep, err := checker.Check(ctx, base, head, sum)
	if err != nil {
		fmt.Fprintln(stderr, "deps-guard: no verdict:", err)
		return exitError
	}
	md := depsguard.RenderMarkdown(rep)
	if *reportPath != "" {
		// #nosec G703 -- the path is the CI caller's own -report flag, not PR data.
		if err := os.WriteFile(*reportPath, []byte(md), 0o600); err != nil {
			fmt.Fprintln(stderr, "deps-guard:", err)
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
