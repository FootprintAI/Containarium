package sentinel

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Fail2BanRunner is the small surface the fail2ban admin handlers
// (Fail2BanBansHandler, Fail2BanUnbanHandler — #1962) need from
// fail2ban-client. It exists as an interface — same pattern as
// pkg/core/incus.MigrationRunner — so tests can substitute canned
// fail2ban-client output/exit codes without a real fail2ban install,
// which most dev sandboxes and CI runners don't have.
type Fail2BanRunner interface {
	// Run executes `fail2ban-client <args...>` and returns its combined
	// stdout+stderr. args are passed straight to exec.Command, never
	// through a shell, so jail names / IP values in them can never be
	// used for command injection. A non-nil err just means
	// fail2ban-client exited non-zero or couldn't run at all —
	// fail2banClientRun below classifies what that means.
	Run(args ...string) (output string, err error)
}

// execFail2BanRunner is the production Fail2BanRunner. It shells out to
// the fail2ban-client CLI on the host — fail2ban-client has no JSON
// mode, so the parsing helpers below work against its text output.
type execFail2BanRunner struct {
	// Path to the fail2ban-client binary. Empty means look on $PATH.
	Path string
}

func (e execFail2BanRunner) Run(args ...string) (string, error) {
	bin := e.Path
	if bin == "" {
		bin = "fail2ban-client"
	}
	// #nosec G204 -- args are fixed subcommand literals ("status", "get",
	// "set", "unbanip", "ignoreip") plus a jail name / IP address that
	// callers validate before this is ever reached (net.ParseIP for IPs;
	// jail names are never interpolated into a shell string — they're a
	// literal argv element). Never exec.Command("sh", "-c", ...).
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

var (
	// errFail2BanUnavailable means this sentinel cannot answer fail2ban
	// questions at all right now — fail2ban-client isn't on $PATH, or
	// it's installed but the fail2ban service it talks to isn't
	// running/reachable. Handlers map this to 404, not 500: it tells a
	// caller "this sentinel cannot do that" rather than reporting a bug.
	errFail2BanUnavailable = errors.New("fail2ban unavailable on this sentinel")

	// errFail2BanJailNotFound means fail2ban-client itself rejected a
	// jail name as unknown (its literal "... does not exist" error).
	// Handlers map this to 404 too, but it's a distinct condition from
	// errFail2BanUnavailable: fail2ban IS available here, the named jail
	// just isn't one it knows about.
	errFail2BanJailNotFound = errors.New("fail2ban jail not found")
)

// fail2banClientRun runs a fail2ban-client subcommand via runner and
// classifies any failure into errFail2BanUnavailable or
// errFail2BanJailNotFound so callers can map errors.Is() straight to
// the right HTTP status. jail is the jail name being addressed (used
// only to build a readable error message) — pass "" for
// jail-independent commands like the top-level `status`.
func fail2banClientRun(runner Fail2BanRunner, jail string, args ...string) (string, error) {
	out, err := runner.Run(args...)
	if err == nil {
		return out, nil
	}
	if strings.Contains(out, "does not exist") {
		if jail == "" {
			jail = "(unknown)"
		}
		return out, fmt.Errorf("%w: %q: %s", errFail2BanJailNotFound, jail, strings.TrimSpace(out))
	}
	return out, fmt.Errorf("%w: %v: %s", errFail2BanUnavailable, err, strings.TrimSpace(out))
}

// fail2banListJails discovers the jails fail2ban-client currently knows
// about on this host, from `fail2ban-client status`'s "Jail list:"
// line. Never hardcoded — this works for whatever jails a given
// sentinel happens to have configured (sshpiperd, sshd, both, or none
// at all), matching #1962's explicit "don't assume a jail name" ask.
func fail2banListJails(runner Fail2BanRunner) ([]string, error) {
	out, err := fail2banClientRun(runner, "", "status")
	if err != nil {
		return nil, err
	}
	return parseJailList(out)
}

// parseJailList extracts jail names from `fail2ban-client status`
// output, e.g.:
//
//	Status
//	|- Number of jail:	2
//	`- Jail list:	sshd, sshpiperd
func parseJailList(out string) ([]string, error) {
	const marker = "Jail list:"
	for _, line := range strings.Split(out, "\n") {
		idx := strings.Index(line, marker)
		if idx == -1 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len(marker):])
		if rest == "" {
			return []string{}, nil
		}
		parts := strings.Split(rest, ",")
		jails := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				jails = append(jails, p)
			}
		}
		return jails, nil
	}
	return nil, fmt.Errorf("%w: could not find %q in fail2ban-client status output: %s", errFail2BanUnavailable, marker, strings.TrimSpace(out))
}

// fail2banJailBanned returns jail's currently-banned IPs, parsed from
// `fail2ban-client status <jail>`'s "Banned IP list:" line.
func fail2banJailBanned(runner Fail2BanRunner, jail string) ([]string, error) {
	out, err := fail2banClientRun(runner, jail, "status", jail)
	if err != nil {
		return nil, err
	}
	return parseBannedIPList(out)
}

// parseBannedIPList extracts the space-separated banned-IP list from
// `fail2ban-client status <jail>` output, e.g.:
//
//	Status for the jail: sshd
//	|- Filter
//	|  ...
//	`- Actions
//	   |- Currently banned:	1
//	   |- Total banned:	3
//	   `- Banned IP list:	203.0.113.7 198.51.100.9
func parseBannedIPList(out string) ([]string, error) {
	const marker = "Banned IP list:"
	for _, line := range strings.Split(out, "\n") {
		idx := strings.Index(line, marker)
		if idx == -1 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len(marker):])
		if rest == "" {
			return []string{}, nil
		}
		return strings.Fields(rest), nil
	}
	return nil, fmt.Errorf("%w: could not find %q in fail2ban-client status output: %s", errFail2BanUnavailable, marker, strings.TrimSpace(out))
}

// fail2banJailIgnoreIP returns jail's configured ignoreip exemptions,
// parsed from `fail2ban-client get <jail> ignoreip`. Returning this
// alongside the ban list matters as much as the bans themselves: it
// answers "why was I bannable at all" (#1962).
func fail2banJailIgnoreIP(runner Fail2BanRunner, jail string) ([]string, error) {
	out, err := fail2banClientRun(runner, jail, "get", jail, "ignoreip")
	if err != nil {
		return nil, err
	}
	return parseIgnoreIPList(out), nil
}

// parseIgnoreIPList parses `fail2ban-client get <jail> ignoreip`
// output. With no exemptions it prints a single line:
//
//	No IP address/network is ignored
//
// With one or more, a tree-drawing list:
//
//	These IP addresses/networks are ignored:
//	|- 127.0.0.0/8
//	`- 10.0.0.0/8
func parseIgnoreIPList(out string) []string {
	entries := []string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "No IP address"):
		case strings.HasPrefix(line, "These IP addresses"):
		case strings.HasPrefix(line, "|-") || strings.HasPrefix(line, "`-"):
			line = strings.TrimPrefix(line, "|-")
			line = strings.TrimPrefix(line, "`-")
			if line = strings.TrimSpace(line); line != "" {
				entries = append(entries, line)
			}
		default:
			entries = append(entries, line)
		}
	}
	return entries
}

// fail2banUnban attempts `fail2ban-client set <jail> unbanip <ip>` and
// reports whether ip was actually banned on jail. Unbanning an address
// that wasn't banned there is success with unbanned=false, not an
// error (#1962): a multi-sentinel deployment normally has the ban on
// only one host, and a caller clearing an address everywhere shouldn't
// have to treat "wasn't banned here" as a failure.
func fail2banUnban(runner Fail2BanRunner, jail, ip string) (bool, error) {
	out, err := fail2banClientRun(runner, jail, "set", jail, "unbanip", ip)
	if err != nil {
		return false, err
	}
	return parseUnbanCount(out), nil
}

// parseUnbanCount parses `fail2ban-client set <jail> unbanip <ip>`'s
// output, which on success is just the count of IPs actually unbanned
// (0 or 1, for a single-IP call).
func parseUnbanCount(out string) bool {
	trimmed := strings.TrimSpace(out)
	return trimmed != "" && trimmed != "0"
}
