//go:build !windows

package cmd

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/server"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Every containarium command `containarium debug` prints must actually parse
// (#1478).
//
// The bug: the missing-host-user remediation recommended
// `sync-accounts --user <name>` while sync-accounts registered only --dry-run
// and --force, so the printed command died with "unknown flag: --user". This
// text is read by someone already locked out, following it literally, and its
// failure invites the reading that the DIAGNOSIS was wrong when only the remedy
// was mistyped.
//
// Nothing structural stops that drift — the strings are fmt.Sprintf literals in
// a different package from the flag definitions — so it has to be a test.

// diagnoseStates covers every branch of Diagnose that can emit a command.
func diagnoseStates() []*pb.DebugContainerResponse {
	return []*pb.DebugContainerResponse{
		{ContainerState: "missing"},
		{ContainerState: "stopped"},
		{ContainerState: "running", HostUserExists: false},
		{ContainerState: "running", HostUserExists: true, HostUserShell: "/usr/local/bin/containarium-shell"},
		{ContainerState: "running", HostUserExists: true, HostUserShell: "/nonexistent", HostUserShellExists: false},
		{ContainerState: "error: incus unreachable"},
		{ContainerState: "running", HostUserExists: true, SshIngressHost: "sentinel.example.com"},
	}
}

// extractContainariumCommands pulls each `containarium ...` invocation out of a
// next_actions line. A line is prose with the command embedded, and may chain
// two commands with &&.
//
// "containarium" also appears as an ARGUMENT to other tools in these hints —
// `journalctl -u containarium -e --no-pager` — so a bare substring match
// mistakes a unit name for a command and then reports a bogus failure. Require
// the following token to look like a subcommand (not a flag) to tell them
// apart.
func extractContainariumCommands(action string) []string {
	var out []string
	for _, chunk := range strings.Split(action, "&&") {
		idx := strings.Index(chunk, "containarium ")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(chunk[idx+len("containarium "):])
		verb, _, _ := strings.Cut(rest, " ")
		if verb == "" || strings.HasPrefix(verb, "-") {
			continue // e.g. `journalctl -u containarium -e` — not an invocation
		}
		out = append(out, "containarium "+rest)
	}
	return out
}

// tokenize splits a command into argv, dropping the leading binary name and
// stopping at placeholders like <pubkey> which are meant to be substituted.
func tokenize(cmdline string) []string {
	fields := strings.Fields(cmdline)
	if len(fields) > 0 && fields[0] == "containarium" {
		fields = fields[1:]
	}
	var argv []string
	for _, f := range fields {
		if strings.HasPrefix(f, "<") {
			// Placeholder value for the preceding flag; supply something that
			// parses so the flag itself is still validated.
			argv = append(argv, "placeholder")
			continue
		}
		argv = append(argv, f)
	}
	return argv
}

func TestDebugRemediationCommandsParse(t *testing.T) {
	for _, report := range diagnoseStates() {
		_, actions := server.Diagnose("alice", report)
		for _, action := range actions {
			for _, cmdline := range extractContainariumCommands(action) {
				t.Run(cmdline, func(t *testing.T) {
					argv := tokenize(cmdline)
					if len(argv) == 0 {
						t.Fatalf("no argv extracted from %q", cmdline)
					}

					// Resolve against the REAL command tree, then parse the
					// flags exactly as cobra would at the terminal.
					target, remaining, err := rootCmd.Find(argv)
					if err != nil {
						t.Fatalf("containarium debug printed %q, but %q is not a known command: %v",
							cmdline, argv[0], err)
					}
					if target == rootCmd {
						t.Fatalf("containarium debug printed %q, but %q did not resolve to a subcommand",
							cmdline, argv[0])
					}
					if err := target.ParseFlags(remaining); err != nil {
						t.Fatalf("containarium debug printed %q, which does not parse: %v\n"+
							"An operator reading this is already locked out and will run it verbatim.",
							cmdline, err)
					}
				})
			}
		}
	}
}

// The missing-host-user case is the one that regressed, and its ordering is
// load-bearing: the list is read top-down by someone locked out, so the
// non-destructive repair must come before delete-and-recreate.
func TestMissingHostUserRemediationIsNonDestructiveFirst(t *testing.T) {
	_, actions := server.Diagnose("alice", &pb.DebugContainerResponse{
		ContainerState: "running",
		HostUserExists: false,
	})
	if len(actions) == 0 {
		t.Fatal("no next_actions for a missing host user")
	}

	firstDestructive, firstRepair := -1, -1
	for i, a := range actions {
		if firstDestructive < 0 && strings.Contains(a, "containarium delete ") {
			firstDestructive = i
		}
		if firstRepair < 0 && strings.Contains(a, "sync-accounts") {
			firstRepair = i
		}
	}
	if firstRepair < 0 {
		t.Fatal("missing-host-user remediation no longer offers sync-accounts, the non-destructive repair")
	}
	if firstDestructive >= 0 && firstDestructive < firstRepair {
		t.Errorf("delete+recreate (action %d) is listed before the sync-accounts repair (action %d); "+
			"the container and its data are intact in this failure mode, so destroying the box must "+
			"never be the first thing an operator reads", firstDestructive, firstRepair)
	}
	if firstDestructive >= 0 && !strings.Contains(actions[firstDestructive], "DESTRUCTIVE") {
		t.Error("the delete+recreate action does not announce itself as destructive")
	}
}

// Guard the specific flag that regressed, so a rename of --user fails here
// rather than in someone's terminal.
func TestSyncAccountsAcceptsTheFlagsDebugRecommends(t *testing.T) {
	for _, flag := range []string{"user", "dry-run", "force"} {
		if syncAccountsCmd.Flags().Lookup(flag) == nil {
			t.Errorf("sync-accounts has no --%s flag; containarium debug recommends it", flag)
		}
	}
}
