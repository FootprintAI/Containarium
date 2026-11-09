package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"

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
src=
for c in /usr/local/bin/agent-box ` + q(ownerHome+"/.local/bin/agent-box") + `; do
  if [ -x "$c" ]; then src=$c; break; fi
done
[ -n "$src" ] || { echo "agent-box is not installed on this box: the command policy cannot be enforced" >&2; exit 1; }
cp -L "$src" "$a/bin/agent-box.new"
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
