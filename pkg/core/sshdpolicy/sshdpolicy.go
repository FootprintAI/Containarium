// Package sshdpolicy is the single source of truth for the SSH-server policy
// Containarium applies inside every box (#2424): the managed drop-in that
// turns password authentication off, and the pure evaluation of an sshd
// configuration against that policy.
//
// It is deliberately IO-free. Box provisioning (pkg/core/container) writes
// DropInContent through the incus file API; the host posture check
// (internal/hostcheck) and the box posture reconciler (internal/security)
// each gather sshd_config + drop-ins their own way and hand the pieces to
// Merge/Evaluate. One parser means the host check and the box check cannot
// disagree about what "password auth is off" means.
//
// Why the box side matters even though the public SSH ingress never reaches
// a box sshd (the sentinel pipes to the backend host sshd, then
// containarium-shell → incus exec): a box owner has NOPASSWD sudo, so one
// `sudo passwd` unlocks password login on a box whose sshd inherited the
// image default `PasswordAuthentication yes`. That sshd is reachable from
// the tenant's own boxes, from the LAN on direct in-network backends, and —
// via any reverse tunnel the owner cares to run — from the internet. The
// drop-in closes that for the stock sshd; the reconciler re-asserts it and
// records tampering as a finding.
package sshdpolicy

import (
	"sort"
	"strings"
)

const (
	// MainConfigPath is sshd's main configuration file.
	MainConfigPath = "/etc/ssh/sshd_config"
	// DropInDir is the Include directory modern distros wire at the TOP of
	// sshd_config, so its files take precedence under first-match-wins.
	DropInDir = "/etc/ssh/sshd_config.d"
	// DropInName sorts before every distro/cloud-init drop-in (50-*.conf),
	// which is what makes it win.
	DropInName = "00-containarium.conf"
	// DropInPath is DropInDir/DropInName.
	DropInPath = DropInDir + "/" + DropInName
	// DropInMode is the file mode the drop-in is written with.
	DropInMode = "0644"

	// MarkerKey is the incus instance config key the posture reconciler
	// sets once a box has been brought under policy. It lives on the host
	// side of the box boundary — a tenant cannot touch it — which is what
	// lets the reconciler tell "never applied yet (backfill, silent)" from
	// "applied before and now gone (tampering, finding)".
	MarkerKey = "user.containarium.sshd_policy"
	// MarkerValue is bumped when the drop-in's meaning changes.
	MarkerValue = "v1"
)

// dropInContent is what DropInContent returns. KbdInteractiveAuthentication
// closes the PAM password prompt that `PasswordAuthentication no` alone
// leaves open; PermitEmptyPasswords is belt-and-braces for an account whose
// password was set to "". The header is the only tenant-facing notice that
// edits do not stick.
const dropInContent = `# Managed by Containarium (#2424). Do not edit: the platform re-asserts this
# file and records changes as a security finding. SSH to a box is key-only.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
`

// DropInContent returns the managed drop-in as bytes.
func DropInContent() []byte { return []byte(dropInContent) }

// DropIn is one file from DropInDir.
type DropIn struct {
	Name    string // base name, e.g. "50-cloud-init.conf"
	Content string
}

// Merge assembles the configuration text in the order sshd reads it: the
// *.conf drop-ins in lexical order (sshd globs them that way) and then the
// main file. Modern distros place the Include at the top of sshd_config, so
// under first-match-wins (see Directive) the drop-ins override the main
// file; get this order backwards and a hardened host reads as unhardened,
// or the reverse. Non-.conf entries are ignored, as sshd ignores them.
func Merge(main string, dropIns []DropIn) string {
	names := make([]DropIn, 0, len(dropIns))
	for _, d := range dropIns {
		if strings.HasSuffix(d.Name, ".conf") {
			names = append(names, d)
		}
	}
	sort.Slice(names, func(i, j int) bool { return names[i].Name < names[j].Name })
	var b strings.Builder
	for _, d := range names {
		b.WriteString(d.Content)
		b.WriteString("\n")
	}
	b.WriteString(main)
	return b.String()
}

// Directive returns the effective value of key in config, or def if unset.
//
// FIRST occurrence wins — that is OpenSSH's rule for these keywords, and
// it is the opposite of the "last wins" most config formats use. Match
// blocks are ignored: a directive inside `Match` is conditional, and
// treating it as global would misreport. Anything after the first Match
// line is skipped. Keys compare case-insensitively, as sshd does.
func Directive(config, key, def string) string {
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "Match") {
			break // conditional territory; stop reading globals
		}
		if strings.EqualFold(fields[0], key) && len(fields) >= 2 {
			return fields[1]
		}
	}
	return def
}

// Violation is one directive whose effective value permits password login.
type Violation struct {
	Directive string
	Value     string
}

func (v Violation) String() string { return v.Directive + "=" + v.Value }

// Result is Evaluate's verdict on one merged configuration.
type Result struct {
	// Violations is empty when the configuration refuses password login.
	Violations []Violation
	// PasswordAuthentication, KbdInteractiveAuthentication and
	// PermitEmptyPasswords are the effective values (sshd defaults applied).
	PasswordAuthentication       string
	KbdInteractiveAuthentication string
	PermitEmptyPasswords         string
}

// Compliant reports whether the configuration refuses password login.
func (r Result) Compliant() bool { return len(r.Violations) == 0 }

// Evaluate judges a merged configuration (see Merge) against the policy.
// The sshd defaults are applied where a directive is absent, which is why a
// bare, image-default sshd_config evaluates as non-compliant: sshd's own
// default for PasswordAuthentication is yes.
func Evaluate(merged string) Result {
	r := Result{
		PasswordAuthentication:       Directive(merged, "PasswordAuthentication", "yes"),
		KbdInteractiveAuthentication: Directive(merged, "KbdInteractiveAuthentication", "yes"),
		PermitEmptyPasswords:         Directive(merged, "PermitEmptyPasswords", "no"),
	}
	if !strings.EqualFold(r.PasswordAuthentication, "no") {
		r.Violations = append(r.Violations, Violation{"PasswordAuthentication", r.PasswordAuthentication})
	}
	if !strings.EqualFold(r.KbdInteractiveAuthentication, "no") {
		r.Violations = append(r.Violations, Violation{"KbdInteractiveAuthentication", r.KbdInteractiveAuthentication})
	}
	if !strings.EqualFold(r.PermitEmptyPasswords, "no") {
		r.Violations = append(r.Violations, Violation{"PermitEmptyPasswords", r.PermitEmptyPasswords})
	}
	return r
}

// ManagedDropInIntact reports whether dropIns contains the managed file
// with exactly the expected content.
func ManagedDropInIntact(dropIns []DropIn) bool {
	for _, d := range dropIns {
		if d.Name == DropInName {
			return d.Content == dropInContent
		}
	}
	return false
}
