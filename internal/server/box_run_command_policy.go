package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/runhook"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Command allowlist and audit events for box runs (#3582). An engine run
// started with command_policy gets the engine's PreToolUse / PostToolUse hooks
// (`agent-box permission-hook`, configured through --settings, which
// --restricted still reads); a command-mode run runs `agent-box
// permission-hook command`, which applies the same decision to the command and
// records the same events. Both get a root-run sink (`agent-box
// run-audit-sink`) that is the only writer of the run's audit file. Everything the hooks and the
// sink read is written as root before the run starts, under a directory the run
// user cannot write; the hooks run a root-owned copy of agent-box, so the run
// user cannot swap them either. At FULL_SUDO the controls are installed and
// decide exactly as at any other level, but they are advisory: the run user
// can become root and step around all of it, as it can the level's own flags.

var boxRunApprovalIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:@-]{1,128}$`)

// validateBoxRunCommandPolicy checks the request's policy fields; it touches
// nothing. Everything here is INVALID_ARGUMENT.
func validateBoxRunCommandPolicy(req *pb.StartBoxRunRequest) error {
	pol, appr := req.GetCommandPolicy(), req.GetApproval()
	if pol == nil && appr == nil {
		return nil
	}
	if appr != nil {
		if pol == nil {
			return status.Error(codes.InvalidArgument, "approval needs command_policy")
		}
		if req.GetSessionId() != "" || req.GetContinueSession() {
			return status.Error(codes.InvalidArgument, "an approved re-run is a new run: approval is refused with session_id or continue_session")
		}
		if !boxRunApprovalIDPattern.MatchString(appr.GetApprovalId()) || !boxRunApprovalIDPattern.MatchString(appr.GetApproverId()) {
			return status.Errorf(codes.InvalidArgument, "approval_id and approver_id must match %s", boxRunApprovalIDPattern.String())
		}
	}
	if _, err := runhook.ParseAllowlist(pol.GetAllow()); err != nil {
		return status.Errorf(codes.InvalidArgument, "command_policy.allow: %v", err)
	}
	if _, err := runhook.NewRedactor(pol.GetRedactPatterns()); err != nil {
		return status.Errorf(codes.InvalidArgument, "command_policy.redact_patterns: %v", err)
	}
	return nil
}

// newBoxRunAuditID is the id of one start of a run: it names the sink's socket
// and tags every event of that start.
func newBoxRunAuditID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// boxRunAuditConfig is what the hooks and the sink of run name read.
func boxRunAuditConfig(name, runID string, level boxRunPolicy, req *pb.StartBoxRunRequest) runhook.Config {
	cfg := runhook.Config{
		RunName:        name,
		RunID:          runID,
		Socket:         runhook.SocketPath(runID),
		EventsPath:     runhook.EventsPath(name),
		ExitPath:       runhook.ExitPath(name),
		Allow:          append([]string(nil), req.GetCommandPolicy().GetAllow()...),
		LevelAllowed:   append([]string(nil), level.Allowed...),
		LevelDenied:    append([]string(nil), level.Denied...),
		RedactPatterns: append([]string(nil), req.GetCommandPolicy().GetRedactPatterns()...),
	}
	if req.GetCommand() != "" {
		cfg.Command = req.GetCommand()
	}
	if a := req.GetApproval(); a != nil {
		cfg.Approval = &runhook.Approval{ID: a.GetApprovalId(), Approver: a.GetApproverId()}
	}
	return cfg
}

// boxRunAuditSetupScript runs as root before the run is spawned: it installs a
// root-owned agent-box (from the box's system install, else the owner's), checks
// it has the hook modes and the run supervisor, clears the run's previous
// root-owned exit status, writes the run's configuration root-owned 0644, starts
// the sink detached, and waits for its socket. Any failure refuses the run.
// The exit directory is root's 0700, like the events directory: only the
// supervisor (root) writes a run's exit status there, and only the sink (root)
// reads it.
func boxRunAuditSetupScript(cfg runhook.Config, runDir, ownerHome string) (string, error) {
	if !validHomePath(ownerHome) {
		return "", fmt.Errorf("refusing owner home %q: not a plain absolute home path", ownerHome)
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	q := shellSingleQuote
	conf := runhook.ConfigPath(cfg.RunName)
	return `set -e
a=` + q(runhook.AuditDir) + `
mkdir -p "$a" "$a/bin" "$a/s" "$a/events" "$a/exit"
chown root:root "$a" "$a/bin" "$a/s" "$a/events" "$a/exit"
chmod 0755 "$a" "$a/bin" "$a/s"
chmod 0700 "$a/events" "$a/exit"
` + boxRunAgentBoxSourceScript([]string{"/usr/local/bin/agent-box", ownerHome + "/.local/bin/agent-box"}, "0") + `
cp -L "$src" "$a/bin/agent-box.new"
[ "$(stat -L -c '%u %A %i %Y %s' "$src")" = "$srcstat" ] || { rm -f "$a/bin/agent-box.new"; echo "agent-box changed while it was copied: refusing it" >&2; exit 1; }
chown root:root "$a/bin/agent-box.new"
chmod 0755 "$a/bin/agent-box.new"
mv -f "$a/bin/agent-box.new" ` + q(runhook.AgentBoxPath) + `
` + q(runhook.AgentBoxPath) + ` permission-hook </dev/null 2>&1 | grep -qF ` + q(runhook.HookUsage) + ` || { echo "agent-box on this box predates the permission hook: update it" >&2; exit 1; }
` + q(runhook.AgentBoxPath) + ` run-supervise </dev/null 2>&1 | grep -qF ` + q(runhook.SuperviseUsage) + ` || { echo "agent-box on this box predates the run supervisor: update it" >&2; exit 1; }
rm -f ` + q(cfg.ExitPath) + ` ` + q(cfg.ExitPath+".tmp") + ` ` + q(runhook.LaunchPath(cfg.RunName)) + `
printf '%s' ` + q(string(cfgJSON)) + ` > ` + q(conf+".new") + `
chown root:root ` + q(conf+".new") + `
chmod 0644 ` + q(conf+".new") + `
mv -f ` + q(conf+".new") + ` ` + q(conf) + `
setsid ` + q(runhook.AgentBoxPath) + ` run-audit-sink --config ` + q(conf) + ` --run-dir ` + q(runDir) + ` </dev/null >/dev/null 2>&1 &
i=0
while [ ! -S ` + q(cfg.Socket) + ` ]; do
  i=$((i+1))
  [ "$i" -le 100 ] || { echo "the audit sink did not start" >&2; exit 1; }
  sleep 0.1
done
`, nil
}

// boxRunAgentBoxSourceScript picks, among candidates, the agent-box that root
// copies and then runs as root. A candidate counts only if it is an executable
// regular file owned by uid (root) and writable by neither group nor others: the
// owner's own ~/.local/bin copy is the owner's to rewrite, so an unchecked one
// would be arbitrary code as root. A candidate that fails the check is skipped
// with a note on stderr; with none left the script exits 1. On success it sets
// $src and $srcstat (the file's owner, mode, inode, mtime and size, which the
// caller compares again after copying to catch a swap).
func boxRunAgentBoxSourceScript(candidates []string, uid string) string {
	return boxRunTrustedSourceScript(candidates, shellSingleQuote(uid+" "), "agent-box",
		"not owned by uid "+uid+" or is group/world-writable",
		"no trusted agent-box is installed on this box (it must be root-owned and not group/world-writable): the command policy cannot be enforced")
}

// boxRunTrustedSourceScript is the check behind boxRunAgentBoxSourceScript:
// uidWord is the shell word the file's owner uid plus a space must equal (a
// quoted literal, or "$var "), what names the file in the notes, and
// badWhy and noneMsg are the messages for a skipped candidate and for none left.
func boxRunTrustedSourceScript(candidates []string, uidWord, what, badWhy, noneMsg string) string {
	q := shellSingleQuote
	quoted := make([]string, len(candidates))
	for i, c := range candidates {
		quoted[i] = q(c)
	}
	return `src=
srcstat=
for c in ` + strings.Join(quoted, " ") + `; do
  [ -f "$c" ] && [ -x "$c" ] || continue
  st=$(stat -L -c '%u %A %i %Y %s' "$c" 2>/dev/null) || continue
  case "$st" in
    ` + uidWord + `?????-??-?' '*) src=$c; srcstat=$st; break ;;
  esac
  echo ` + q(what+" at ") + `"$c ` + badWhy + `: skipping it" >&2
done
[ -n "$src" ] || { echo ` + q(noneMsg) + ` >&2; exit 1; }`
}

// BoxRunViolationEngineNotRootStaged is the typed reason a run under a command
// policy is refused when the engine cannot be staged as a root-owned copy. It
// is the Type of a google.rpc.PreconditionFailure violation in the error's
// details. The value is a stable contract.
const BoxRunViolationEngineNotRootStaged = "ENGINE_NOT_ROOT_STAGED"

// boxRunEngineStageScript is run as root before a policy run: it installs the
// owner's engine (~/.local/bin/claude, dereferenced) as runhook.EnginePath, a
// root-owned 0755 copy in the root-owned audit directory. The run user's own
// staged engine is writable by it, so an agent could replace that one in run N
// and run N+1 would start without the hooks; the run executes this copy
// instead. The owner's copy is trusted only like the agent-box source: a
// regular executable owned by the box owner (never the run user, never root's
// choice of another uid) and writable by neither group nor others. The copy is
// re-checked against the source after it is made, and is replaced when the
// owner's file changes (its owner, mode, inode, mtime or size, kept in a
// root-owned marker next to it) or when the staged copy is no longer exactly
// root-owned 0755. Any failure exits 1: there is no fallback.
func boxRunEngineStageScript(ownerHome string) (string, error) {
	return boxRunEngineStageScriptFor(ownerHome, runhook.AuditDir, boxRunUnprivilegedUser, "0", "root:root")
}

// boxRunEngineStageScriptFor is boxRunEngineStageScript with the audit
// directory, run user and root identity as parameters (tests run it as an
// ordinary user in a temporary directory).
func boxRunEngineStageScriptFor(ownerHome, auditDir, runUser, rootUID, rootOwner string) (string, error) {
	if !validHomePath(ownerHome) {
		return "", fmt.Errorf("refusing owner home %q: not a plain absolute home path", ownerHome)
	}
	q := shellSingleQuote
	return `set -e
a=` + q(auditDir) + `
mkdir -p "$a" "$a/bin"
chown ` + q(rootOwner) + ` "$a" "$a/bin"
chmod 0755 "$a" "$a/bin"
ru=$(id -u ` + q(runUser) + ` 2>/dev/null || true)
ou=$(stat -L -c %u ` + q(ownerHome) + `) || { echo "cannot read the box owner's home" >&2; exit 1; }
[ -n "$ou" ] && [ "$ou" != "$ru" ] || { echo "the box owner's uid is the run user's: no engine can be trusted" >&2; exit 1; }
` + boxRunTrustedSourceScript([]string{ownerHome + "/.local/bin/claude"}, `"$ou "`, "engine",
		"is not owned by the box owner or is group/world-writable",
		"no trusted engine is installed for the box owner (it must be owned by the owner and not group/world-writable): the command policy cannot be enforced") + `
d="$a/bin/claude"
m="$a/bin/claude.src"
want=` + q(rootUID+" -rwxr-xr-x") + `
if [ "$(stat -c '%u %A' "$d" 2>/dev/null)" = "$want" ] && [ "$(cat "$m" 2>/dev/null)" = "$srcstat" ]; then
  :
else
  rm -f "$d.new" "$m.new"
  cp -L "$src" "$d.new"
  [ "$(stat -L -c '%u %A %i %Y %s' "$src")" = "$srcstat" ] || { rm -f "$d.new"; echo "the engine changed while it was copied: refusing it" >&2; exit 1; }
  chown ` + q(rootOwner) + ` "$d.new"
  chmod 0755 "$d.new"
  mv -f "$d.new" "$d"
  printf '%s' "$srcstat" > "$m.new"
  chown ` + q(rootOwner) + ` "$m.new"
  chmod 0644 "$m.new"
  mv -f "$m.new" "$m"
fi
[ "$(stat -c '%u %A' "$d")" = "$want" ] || { echo "the staged engine is not root-owned 0755: refusing it" >&2; exit 1; }
[ "$(stat -c '%u %A' "$a/bin")" = ` + q(rootUID+" drwxr-xr-x") + ` ] || { echo "the engine directory is not root-owned 0755: refusing it" >&2; exit 1; }
`, nil
}

// boxRunEngineStageRefusal is the FailedPrecondition returned when the engine
// cannot be staged root-owned.
func boxRunEngineStageRefusal(username string, cause error) error {
	msg := fmt.Sprintf("the command policy needs the engine as a root-owned copy the run user cannot write, and %q has none: %v", username, cause)
	st := status.New(codes.FailedPrecondition, msg)
	if detailed, err := st.WithDetails(&errdetails.PreconditionFailure{
		Violations: []*errdetails.PreconditionFailure_Violation{{Type: BoxRunViolationEngineNotRootStaged, Subject: username, Description: msg}},
	}); err == nil {
		st = detailed
	}
	return st.Err()
}

// boxRunPolicyEngineCommand points the engine command at the root-staged copy.
// Nothing is left on the run user's own copy; if the command does not name the
// engine where expected it is an error, never a command that runs another one.
func boxRunPolicyEngineCommand(command string) (string, error) {
	const own = "~/.local/bin/claude"
	if !strings.Contains(command, own+" ") {
		return "", fmt.Errorf("the engine command does not run %s: cannot point it at the root-owned copy", own)
	}
	command = strings.ReplaceAll(command, own+" ", runhook.EnginePath+" ")
	if strings.Contains(command, own) {
		return "", fmt.Errorf("the engine command still references %s", own)
	}
	return command, nil
}

type boxRunHookCommand struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

type boxRunHookMatcher struct {
	Matcher string              `json:"matcher"`
	Hooks   []boxRunHookCommand `json:"hooks"`
}

type boxRunHookSettings struct {
	Hooks map[string][]boxRunHookMatcher `json:"hooks"`
}

// boxRunHookSettingsJSON is the --settings value that installs run name's
// hooks: the pre hook before every shell command, the post hook after it
// whether it succeeded or failed.
func boxRunHookSettingsJSON(name string) string {
	conf := shellSingleQuote(runhook.ConfigPath(name))
	hook := func(kind string) []boxRunHookMatcher {
		return []boxRunHookMatcher{{Matcher: "Bash", Hooks: []boxRunHookCommand{{
			Type: "command", Command: runhook.AgentBoxPath + " permission-hook " + kind + " --config " + conf,
		}}}}
	}
	b, _ := json.Marshal(boxRunHookSettings{Hooks: map[string][]boxRunHookMatcher{
		"PreToolUse":         hook("pre"),
		"PostToolUse":        hook("post"),
		"PostToolUseFailure": hook("post"),
	}})
	return string(b)
}

// setUpBoxRunAudit writes run name's root-owned configuration and starts its
// sink, as root, before anything is spawned: the run must not start before its
// first command can be recorded.
func setUpBoxRunAudit(listExec boxScriptFunc, box, dir, name, ownerHome, username string, level boxRunPolicy, req *pb.StartBoxRunRequest) error {
	runID, err := newBoxRunAuditID()
	if err != nil {
		return status.Errorf(codes.Internal, "run audit id: %v", err)
	}
	// An engine run executes a root-owned copy of the engine, staged before
	// anything else is set up so a refusal leaves no sink behind. A command-mode
	// run starts no engine.
	if req.GetCommand() == "" {
		stage, err := boxRunEngineStageScript(ownerHome)
		if err != nil {
			return boxRunEngineStageRefusal(username, err)
		}
		if _, err := listExec(box, stage); err != nil {
			return boxRunEngineStageRefusal(username, err)
		}
	}
	setup, err := boxRunAuditSetupScript(boxRunAuditConfig(name, runID, level, req), dir, ownerHome)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "%q: %v", username, err)
	}
	if _, err := listExec(box, setup); err != nil {
		return status.Errorf(codes.FailedPrecondition, "set up the command policy on %q: %v", username, err)
	}
	return nil
}

// boxRunPolicyCommandLine is a command-mode run's line under a command policy:
// the root-owned agent-box decides and runs the configured command, under the
// same timeout as a plain command run.
func boxRunPolicyCommandLine(name string, timeoutSeconds int) string {
	return coderun.BuildTimedCommand(runhook.AgentBoxPath+" permission-hook command --config "+shellSingleQuote(runhook.ConfigPath(name)), timeoutSeconds)
}
