package server

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/footprintai/containarium/internal/coderun/engine"
	"github.com/footprintai/containarium/pkg/core/box"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Platform-started runs on a box with a recorded tool-access level execute as a
// dedicated unprivileged OS user instead of the box's owner (#2944, slice 1b).
// The owner's login keeps its sudo; this user never has any, so a policy file
// only root can write (a later slice) is a real boundary for the run. A box
// with NO recorded level keeps today's path exactly.
//
// What a run reads from "its" home — the agent CLI, the MCP config, the credential
// helper — lives under the OWNER's $HOME on a bootstrapped box, so the run user
// gets its own staged copy of that NON-Claude configuration.
//
// The platform never reads, copies, refreshes or stores a Claude login (Anthropic's
// terms forbid a platform collecting, storing or intermediating one; see #2036).
// The run user signs in ONCE through Anthropic's own flow, as itself; the platform
// only checks, by the existing credential-status probe, that a usable sign-in is
// there, and refuses the run with an actionable message when it is not (never
// signed in, or expired) so the box's owner can be told to sign in again.

// boxRunUnprivilegedUser is the OS user such runs execute as. A fixed name: the
// daemon creates it lazily on the first such run, so existing boxes need no backfill.
const boxRunUnprivilegedUser = "ctn-run"

// boxRunRecordedToolAccess reports the tool-access level recorded for username's
// box ("" = none recorded, the legacy path). The fn seam is for tests; production
// reads the Incus config through the box backend. A read error is returned, never
// swallowed into "", so a transient failure cannot silently demote a run to the
// owner's identity.
func (s *ContainerServer) boxRunRecordedToolAccess(ctx context.Context, username string) (string, error) {
	if s.boxRunToolAccess != nil {
		return s.boxRunToolAccess(ctx, username)
	}
	if s.manager == nil && s.boxBackend == nil {
		return "", nil
	}
	info, err := s.boxes().Get(ctx, box.BoxRef{Tenant: username})
	if err != nil {
		return "", err
	}
	if info == nil {
		return "", nil
	}
	return info.ToolAccess, nil
}

// safeHomePath is what a home directory must look like before it is spliced into
// a root script (and into a sed expression). Absolute, no spaces or shell/sed
// metacharacters.
var safeHomePath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

func validHomePath(p string) bool {
	return safeHomePath.MatchString(p) && !strings.Contains(p, "..") && !strings.HasSuffix(p, "/")
}

// boxRunProvisionScript is run as root. Idempotent: creates the run user if it
// is absent, locks its password, makes its home private, and takes it out of
// every group that is root-equivalent. Prints the run user's home on its last
// line.
func boxRunProvisionScript() string {
	u := boxRunUnprivilegedUser
	return `set -e
u=` + u + `
if ! id -u "$u" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --user-group "$u"
fi
passwd -l "$u" >/dev/null 2>&1 || true
h=$(getent passwd "$u" | cut -d: -f6)
[ -n "$h" ] && [ -d "$h" ] || { echo "run user has no home" >&2; exit 1; }
chmod 0700 "$h"
for g in sudo wheel admin docker podman lxd adm; do gpasswd -d "$u" "$g" >/dev/null 2>&1 || true; done
printf '%s\n' "$h"
`
}

// boxRunDirScript is run as root: the run directory must exist and be writable
// by the run user as well as the owner. Sticky and world-writable like /tmp: the
// files in it are created 0600, and only their creator (or root) may rename or
// remove them.
func boxRunDirScript(dir string) string {
	q := shellSingleQuote
	return "set -e\nmkdir -p " + q(dir) + "\nchmod 1777 " + q(dir) + "\n"
}

// boxRunStagedPlatformCredentials are the PLATFORM'S OWN credential for the
// box (the box principal token its git credential helper and skills MCP server
// present to the control plane), copied from the owner's home. It is not a Claude
// login. Relative to $HOME. Written atomically and left in place: nothing deletes
// it per run, so a run that ends cannot pull it from under one still going.
var boxRunStagedPlatformCredentials = []string{
	".config/containarium/box-token",
}

// boxRunStagedBinaries are copied (dereferenced: the agent CLI is installed as a
// symlink into a versioned directory the run user cannot read) only when missing
// or older than the owner's. They hold no secret and stay between runs.
var boxRunStagedBinaries = []string{
	".local/bin/claude",
	".local/bin/box-credential-helper",
	".local/bin/skill-mcp-server",
}

// boxRunStagedConfig are text files that name the owner's home in absolute
// paths, so they are copied with that prefix rewritten to the run user's home.
// They hold no secret.
var boxRunStagedConfig = []string{
	".claude/containarium-mcp.json",
	".claude/settings.json",
	".gitconfig",
	".config/containarium/manifest.json",
}

// boxRunStageScript is run as root before each run: it brings the run user's home
// up to date from the owner's. Missing source files are skipped (a box need not
// have every one). Everything is owned by the run user and unreadable to others.
func boxRunStageScript(ownerHome, runHome string) (string, error) {
	if !validHomePath(ownerHome) || !validHomePath(runHome) {
		return "", fmt.Errorf("refusing to stage between %q and %q: not a plain absolute home path", ownerHome, runHome)
	}
	if ownerHome == runHome {
		return "", fmt.Errorf("the run user's home must differ from the owner's (%q)", ownerHome)
	}
	q := shellSingleQuote
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString("o=" + q(ownerHome) + "\nr=" + q(runHome) + "\nu=" + boxRunUnprivilegedUser + "\n")
	b.WriteString(`mkdir -p "$r/.local/bin" "$r/.claude" "$r/.config/containarium"
chown "$u:$u" "$r/.local" "$r/.local/bin" "$r/.claude" "$r/.config" "$r/.config/containarium"
chmod 0700 "$r/.config/containarium"
`)
	for _, rel := range boxRunStagedBinaries {
		b.WriteString("if [ -e \"$o/" + rel + "\" ]; then if [ ! -x \"$r/" + rel + "\" ] || [ \"$o/" + rel + "\" -nt \"$r/" + rel + "\" ]; then " +
			"cp -pL \"$o/" + rel + "\" \"$r/" + rel + ".new\" && chown \"$u:$u\" \"$r/" + rel + ".new\" && chmod 0755 \"$r/" + rel + ".new\" && mv -f \"$r/" + rel + ".new\" \"$r/" + rel + "\"; fi; fi\n")
	}
	for _, rel := range boxRunStagedConfig {
		b.WriteString("if [ -f \"$o/" + rel + "\" ]; then (umask 077; sed \"s|$o|$r|g\" \"$o/" + rel + "\" > \"$r/" + rel + "\"); chown \"$u:$u\" \"$r/" + rel + "\"; chmod 0600 \"$r/" + rel + "\"; fi\n")
	}
	for _, rel := range boxRunStagedPlatformCredentials {
		b.WriteString("if [ -f \"$o/" + rel + "\" ]; then (umask 077; cat \"$o/" + rel + "\" > \"$r/" + rel + ".new\") && chown \"$u:$u\" \"$r/" + rel + ".new\" && chmod 0600 \"$r/" + rel + ".new\" && mv -f \"$r/" + rel + ".new\" \"$r/" + rel + "\"; fi\n")
	}
	// The skills layout: a plain tree, refreshed each run.
	b.WriteString("if [ -d \"$o/.claude/skills\" ]; then rm -rf \"$r/.claude/skills\"; cp -R \"$o/.claude/skills\" \"$r/.claude/skills\"; chown -R \"$u:$u\" \"$r/.claude/skills\"; fi\n")
	return b.String(), nil
}

// boxRunSignInState reports, as the run user, whether the agent CLI has a usable
// sign-in. It runs the engine's existing credential-status probe under the #2790
// alert policy (a login counts as expired only once it is more than a day past
// expiry, because the CLI refreshes an access token by itself), which prints ONE
// word and never reads or prints a credential value.
func boxRunSignInState(startExec boxRunStartFunc, box string) (engine.CredentialStatusSource, error) {
	script, ok := engine.CredentialAlertStatusScript(engine.NameClaude)
	if !ok {
		return "", fmt.Errorf("no credential-status probe for the %s engine", engine.NameClaude)
	}
	out, err := startExec(box, boxRunUnprivilegedUser, script)
	if err != nil {
		return "", err
	}
	return engine.ParseCredentialStatusSource(strings.TrimSpace(out))
}

// boxRunSignInMessage is what the owner is told when the run user has no usable
// sign-in. The platform does not sign in for them and does not copy their own
// login: they complete Anthropic's flow once, as the run user.
func boxRunSignInMessage(state engine.CredentialStatusSource, runHome string) string {
	why := "has never been signed in"
	if state == engine.CredentialStatusExpired {
		why = "sign-in has expired"
	}
	return fmt.Sprintf("the unprivileged run user (%s) %s. Sign in once, as that user, through Anthropic's own flow: "+
		"ssh to the box and run `sudo -iu %s %s/.local/bin/claude auth login`. "+
		"The platform never reads, copies or refreshes a Claude login.", boxRunUnprivilegedUser, why, boxRunUnprivilegedUser, runHome)
}

// The typed reasons a run is refused for want of a usable run-user sign-in. They
// are carried as the Type of a google.rpc.PreconditionFailure violation in the
// error's details, so a caller (the hosted control plane) can tell the box's owner
// to sign in again without matching on message text. Values are a stable contract.
const (
	// BoxRunViolationRunUserNotSignedIn: the run user has never signed in.
	BoxRunViolationRunUserNotSignedIn = "RUN_USER_NOT_SIGNED_IN"
	// BoxRunViolationRunUserSignInExpired: the run user's sign-in has expired.
	BoxRunViolationRunUserSignInExpired = "RUN_USER_SIGN_IN_EXPIRED"
)

// boxRunSignInRefusal is the FailedPrecondition returned for a run user without a
// usable sign-in: the actionable message for people, and the typed violation for
// callers.
func boxRunSignInRefusal(boxName string, state engine.CredentialStatusSource, runHome string) error {
	msg := boxRunSignInMessage(state, runHome)
	violation := BoxRunViolationRunUserNotSignedIn
	if state == engine.CredentialStatusExpired {
		violation = BoxRunViolationRunUserSignInExpired
	}
	st := status.New(codes.FailedPrecondition, msg)
	if detailed, err := st.WithDetails(&errdetails.PreconditionFailure{
		Violations: []*errdetails.PreconditionFailure_Violation{{Type: violation, Subject: boxName, Description: msg}},
	}); err == nil {
		st = detailed
	}
	return st.Err()
}
