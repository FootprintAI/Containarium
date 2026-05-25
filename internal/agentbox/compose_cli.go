package agentbox

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CLI entry-points for the compose-autostart operations.
//
// agent-box is primarily a stdio MCP server, but Phase C of the
// compose-autostart design (FootprintAI/Containarium#317) needs the
// daemon to drive these same operations from outside the LXC. The
// daemon's path is: SSH-exec into the LXC, run
// `agent-box compose <verb>`, parse the JSON on stdout.
//
// To avoid duplicating the systemd/podman logic the MCP handlers
// already encode, the CLI verbs are thin wrappers over the SAME inner
// Go funcs (discoverStacks, installComposeUnit, systemctlUser, etc.)
// the MCP handlers call. Only the input/output framing differs:
//
//   - inputs come from `flag.NewFlagSet`, not MCP `req.GetArguments()`
//   - outputs go as JSON-on-stdout + errors on stderr + exit code,
//     instead of MCP `NewToolResultText` / `NewToolResultError`
//
// The MCP and CLI surfaces are independent — neither calls the other.
// This keeps the CLI free of the mark3labs/mcp-go dependency at the
// call-site level (the package still imports it for the MCP funcs;
// only the CLI dispatch is decoupled).
//
// Wire shape on stdout is always a single JSON object:
//
//   {"ok": true,  ...result fields...}        for success
//   {"ok": false, "error": "<message>"}       for runtime failure
//
// The daemon-side ComposeAutostartService handlers (Phase C, not yet
// shipped) parse this shape and map it back to gRPC responses /
// status codes.

// RunComposeCLI dispatches `agent-box compose <verb> [flags]`. Returns
// the desired process exit code (0 on success, non-zero otherwise).
// Writes JSON to `stdout` and human-readable errors to `stderr`.
//
// Split out from main so tests can drive it without re-exec'ing the
// binary.
func RunComposeCLI(argv []string, stdout, stderr io.Writer) int {
	if len(argv) < 1 {
		fmt.Fprintln(stderr, "usage: agent-box compose <discover|enable|disable|status> [flags]")
		return 2
	}
	verb := argv[0]
	rest := argv[1:]
	switch verb {
	case "discover":
		return runComposeDiscoverCLI(rest, stdout, stderr)
	case "enable":
		return runComposeEnableCLI(rest, stdout, stderr)
	case "disable":
		return runComposeDisableCLI(rest, stdout, stderr)
	case "status":
		return runComposeStatusCLI(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown compose verb: %q (want: discover|enable|disable|status)\n", verb)
		return 2
	}
}

// writeOK emits the success JSON envelope. Errors writing to stdout
// are swallowed — at this point the process is exiting anyway and the
// caller (daemon) will surface a "no JSON received" error of its own.
func writeOK(w io.Writer, result any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"ok":     true,
		"result": result,
	})
}

// writeErr emits the failure JSON envelope AND prints the same
// message to stderr so an operator running the CLI by hand sees it
// even if their shell is gobbling stdout. Returns the exit code.
func writeErr(stdout, stderr io.Writer, format string, args ...any) int {
	msg := fmt.Sprintf(format, args...)
	_ = json.NewEncoder(stdout).Encode(map[string]any{
		"ok":    false,
		"error": msg,
	})
	fmt.Fprintln(stderr, msg)
	return 1
}

// ----- discover -----------------------------------------------------

func runComposeDiscoverCLI(argv []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("compose discover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "", "Root dir to walk (default: $HOME)")
	maxDepth := fs.Int("max-depth", defaultMaxDepth, "Max directory depth")
	noSkip := fs.Bool("no-skip", false, "Don't apply the default skip set")
	var extraSkip stringSliceFlag
	fs.Var(&extraSkip, "skip", "Extra directory name to skip (repeatable)")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *root == "" {
		*root = homeDir()
	}

	skipSet := map[string]struct{}{}
	if !*noSkip {
		for _, d := range defaultSkip {
			skipSet[d] = struct{}{}
		}
	}
	for _, d := range extraSkip {
		skipSet[d] = struct{}{}
	}

	stacks, err := discoverStacks(*root, *maxDepth, skipSet)
	if err != nil {
		return writeErr(stdout, stderr, "compose discover: %v", err)
	}

	bin := resolveComposeBin()
	for i := range stacks {
		stacks[i].ComposeBin = bin
		if bin != "" {
			r, t := composeServiceCounts(bin, stacks[i].ComposeDir)
			stacks[i].RunningCount, stacks[i].TotalCount = r, t
		}
		fillAutostartStatus(&stacks[i])
	}

	writeOK(stdout, map[string]any{"stacks": stacks})
	return 0
}

// ----- enable -------------------------------------------------------

func runComposeEnableCLI(argv []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("compose enable", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "Compose directory (required)")
	force := fs.Bool("force", false, "Re-install the unit even if already enabled")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *dir == "" {
		return writeErr(stdout, stderr, "compose enable: --dir is required")
	}
	d := expandUser(*dir)
	abs, err := filepath.Abs(d)
	if err != nil {
		return writeErr(stdout, stderr, "resolve dir: %v", err)
	}
	if !hasComposeFile(abs) {
		return writeErr(stdout, stderr, "no docker-compose.yml / compose.yml found under %s", abs)
	}

	bin := resolveComposeBin()
	if bin == "" {
		return writeErr(stdout, stderr, "no compose runtime found on PATH (looked for podman-compose, docker compose, podman compose)")
	}

	slug := stackSlug(abs)
	unitInstance := "containarium-compose@" + slug + ".service"

	if !*force && unitEnabled(unitInstance) {
		writeOK(stdout, map[string]any{
			"unit":        unitInstance,
			"dir":         abs,
			"compose_bin": bin,
			"already":     true,
			"message":     "already enabled (use --force to refresh)",
		})
		return 0
	}

	if err := installComposeUnit(bin, *force); err != nil {
		return writeErr(stdout, stderr, "install unit template: %v", err)
	}
	if err := enableLinger(); err != nil {
		// Not fatal — autostart still works while user is logged in.
		// Surface the warning in the result so an operator can fix it
		// (typically needs root sudo).
		_ = err
	}
	if err := systemctlUser("daemon-reload"); err != nil {
		return writeErr(stdout, stderr, "daemon-reload: %v", err)
	}
	if err := systemctlUser("enable", "--now", unitInstance); err != nil {
		return writeErr(stdout, stderr, "enable %s: %v", unitInstance, err)
	}

	writeOK(stdout, map[string]any{
		"unit":        unitInstance,
		"dir":         abs,
		"compose_bin": bin,
		"already":     false,
	})
	return 0
}

// ----- disable ------------------------------------------------------

func runComposeDisableCLI(argv []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("compose disable", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "Compose directory (required)")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *dir == "" {
		return writeErr(stdout, stderr, "compose disable: --dir is required")
	}
	d := expandUser(*dir)
	abs, _ := filepath.Abs(d)
	slug := stackSlug(abs)
	unitInstance := "containarium-compose@" + slug + ".service"

	if !unitEnabled(unitInstance) {
		writeOK(stdout, map[string]any{
			"unit":    unitInstance,
			"dir":     abs,
			"already": true,
			"message": "not enabled (nothing to do)",
		})
		return 0
	}

	if err := systemctlUser("disable", "--now", unitInstance); err != nil {
		return writeErr(stdout, stderr, "disable %s: %v", unitInstance, err)
	}
	writeOK(stdout, map[string]any{
		"unit":    unitInstance,
		"dir":     abs,
		"already": false,
	})
	return 0
}

// ----- status -------------------------------------------------------

func runComposeStatusCLI(argv []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("compose status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "Compose directory (required)")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *dir == "" {
		return writeErr(stdout, stderr, "compose status: --dir is required")
	}
	d := expandUser(*dir)
	abs, _ := filepath.Abs(d)

	cf, ok := findComposeFile(abs)
	if !ok {
		return writeErr(stdout, stderr, "no compose file under %s", abs)
	}

	bin := resolveComposeBin()
	stack := ComposeStack{
		ComposeDir:  abs,
		ComposeFile: cf,
		ComposeBin:  bin,
	}
	if info, err := os.Stat(cf); err == nil {
		stack.ComposeModifiedAt = info.ModTime().UTC().Format(time.RFC3339)
	}
	if bin != "" {
		stack.RunningCount, stack.TotalCount = composeServiceCounts(bin, abs)
	}
	fillAutostartStatus(&stack)

	writeOK(stdout, stack)
	return 0
}

// ----- helper types -------------------------------------------------

// stringSliceFlag implements flag.Value for repeatable string flags.
// Same shape as cobra's StringSliceVar but without the cobra dep.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error { *s = append(*s, v); return nil }
