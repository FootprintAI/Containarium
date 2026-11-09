//go:build !containarium_client

package server

import (
	"context"
	"encoding/json"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/runhook"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// policyCall is one exec against the box, in order: root or as a user.
type policyCall struct {
	root   bool
	script string
}

type policyReqRun struct {
	calls []policyCall
	err   error
}

// spawn is the call that launches the run: the root supervisor's launch under
// a command policy, else the run user's own setsid spawn.
func (r policyReqRun) spawn() (int, string) {
	for i, c := range r.calls {
		if (c.root && strings.Contains(c.script, "run-supervise --config '")) || (!c.root && strings.Contains(c.script, "setsid sh -c")) {
			return i, c.script
		}
	}
	return -1, ""
}

func (r policyReqRun) auditSetup() (int, string) {
	for i, c := range r.calls {
		if c.root && strings.Contains(c.script, runhook.AuditDir) {
			return i, c.script
		}
	}
	return -1, ""
}

// runPolicyReq runs StartBoxRun with req against recording fakes, at level.
func runPolicyReq(t *testing.T, level string, req *pb.StartBoxRunRequest) policyReqRun {
	t.Helper()
	var mu sync.Mutex
	var r policyReqRun
	s := &ContainerServer{
		boxRunLogDir:          t.TempDir(),
		boxRunCollaborator:    func(owner, subject string) (bool, error) { return false, nil },
		boxRunToolAccess:      func(ctx context.Context, username string) (string, error) { return level, nil },
		boxRunEnsureToolchain: func(string) error { return nil },
		boxRunExec: func(box, script string) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			r.calls = append(r.calls, policyCall{root: true, script: script})
			switch {
			case strings.Contains(script, "useradd"):
				return "/srv/" + boxRunUnprivilegedUser + "\n", nil
			case strings.Contains(script, "run-supervise --config '"):
				return "4242 boot-1\n", nil
			}
			return "", nil
		},
		boxRunStartExec: func(box, username, script string) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			r.calls = append(r.calls, policyCall{script: script})
			switch {
			case script == boxRunHomeAndConfigScript():
				return "/srv/alice\n" + claudeCfg, nil
			case script == signInProbeScript(t):
				return "interactive\n", nil
			case strings.Contains(script, "setsid"):
				return "4242 boot-1\n", nil
			}
			return "", nil
		},
	}
	if req.Username == "" {
		req.Username = "alice"
	}
	if req.Prompt == "" && req.Command == "" {
		req.Prompt = "do it"
	}
	_, r.err = s.StartBoxRun(adminCtx(), req)
	return r
}

func withPolicy(allow ...string) *pb.AgentCommandPolicy {
	return &pb.AgentCommandPolicy{Allow: allow}
}

// Requests the daemon refuses before touching the box.
func TestStartBoxRun_CommandPolicy_InvalidRequests(t *testing.T) {
	appr := &pb.AgentRunApproval{ApprovalId: "appr-1", ApproverId: "user-7"}
	for name, req := range map[string]*pb.StartBoxRunRequest{
		"approval with command mode":   {Command: "true", Approval: appr},
		"approval without policy":      {Approval: appr},
		"approval resumes a session":   {CommandPolicy: withPolicy(), Approval: appr, SessionId: "s1"},
		"approval continues a session": {CommandPolicy: withPolicy(), Approval: appr, ContinueSession: true},
		"approval id empty":            {CommandPolicy: withPolicy(), Approval: &pb.AgentRunApproval{ApproverId: "u"}},
		"approver id with a space":     {CommandPolicy: withPolicy(), Approval: &pb.AgentRunApproval{ApprovalId: "a", ApproverId: "u v"}},
		"allow entry with an operator": {CommandPolicy: withPolicy("make lint; rm -rf /")},
		"bad redaction pattern":        {CommandPolicy: &pb.AgentCommandPolicy{RedactPatterns: []string{"("}}},
	} {
		t.Run(name, func(t *testing.T) {
			r := runPolicyReq(t, "none", req)
			if status.Code(r.err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", r.err)
			}
			if len(r.calls) != 0 {
				t.Errorf("a refused request must not touch the box: %d calls", len(r.calls))
			}
		})
	}
}

// The hooks need the level's own rules and the unprivileged run user, so a box
// without a recorded level is refused before anything is mutated.
func TestStartBoxRun_CommandPolicy_RequiresARecordedLevel(t *testing.T) {
	r := runPolicyReq(t, "", &pb.StartBoxRunRequest{CommandPolicy: withPolicy("make lint")})
	if status.Code(r.err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", r.err)
	}
	for _, c := range r.calls {
		for _, m := range []string{"useradd", "mkdir", "chmod", "setsid", runhook.AuditDir} {
			if strings.Contains(c.script, m) {
				t.Errorf("refused run mutated the box (%q):\n%s", m, c.script)
			}
		}
	}
}

func TestStartBoxRun_CommandPolicy_InstallsHooksAndRootSinkBeforeTheRun(t *testing.T) {
	req := &pb.StartBoxRunRequest{
		RunName: "fix-1",
		CommandPolicy: &pb.AgentCommandPolicy{
			Allow:          []string{"make lint", "go test *"},
			RedactPatterns: []string{`acme-[0-9]{6}`},
		},
		Approval: &pb.AgentRunApproval{ApprovalId: "appr-1", ApproverId: "user-7"},
	}
	r := runPolicyReq(t, "none", req)
	if r.err != nil {
		t.Fatal(r.err)
	}
	si, spawn := r.spawn()
	ai, setup := r.auditSetup()
	if si < 0 || ai < 0 {
		t.Fatalf("spawn at %d, audit setup at %d: both must run", si, ai)
	}
	if ai > si {
		t.Error("the sink must be running before the run is spawned")
	}

	// The setup is root's: a root-owned copy of agent-box, a root-owned config,
	// a 0700 events directory, and the sink started detached as root.
	for _, want := range []string{
		"chown root:root", "chmod 0700 \"$a/events\"", runhook.AgentBoxPath, "run-audit-sink",
		runhook.ConfigPath("fix-1"), "setsid", "chmod 0644",
	} {
		if !strings.Contains(setup, want) {
			t.Errorf("audit setup lacks %q:\n%s", want, setup)
		}
	}
	if out, err := exec.Command("sh", "-n", "-c", setup).CombinedOutput(); err != nil {
		t.Errorf("audit setup does not parse: %v\n%s", err, out)
	}

	// The configuration it writes carries the allowlist, the level's own rules,
	// the operator's redactions and the approval.
	cfg := configFromSetup(t, setup)
	if !slices.Equal(cfg.Allow, req.CommandPolicy.Allow) || !slices.Equal(cfg.RedactPatterns, req.CommandPolicy.RedactPatterns) {
		t.Errorf("config allow/redact = %q / %q", cfg.Allow, cfg.RedactPatterns)
	}
	if cfg.Approval == nil || cfg.Approval.ID != "appr-1" || cfg.Approval.Approver != "user-7" {
		t.Errorf("config approval = %+v", cfg.Approval)
	}
	p, _ := boxRunPolicyFor("none")
	if !slices.Equal(cfg.LevelAllowed, p.Allowed) || !slices.Equal(cfg.LevelDenied, p.Denied) {
		t.Error("config level rules differ from the level's policy")
	}
	if cfg.RunName != "fix-1" || len(cfg.RunID) != 16 || cfg.Socket != runhook.SocketPath(cfg.RunID) || cfg.EventsPath != runhook.EventsPath("fix-1") {
		t.Errorf("config identity/paths = %+v", cfg)
	}

	// The run's command carries the hook pair as --settings, ahead of the
	// variadic rule lists.
	settings := settingsFromSpawn(t, spawn)
	for _, ev := range []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"} {
		ms := settings.Hooks[ev]
		if len(ms) != 1 || ms[0].Matcher != "Bash" || len(ms[0].Hooks) != 1 {
			t.Fatalf("hooks[%s] = %+v", ev, ms)
		}
		cmd := ms[0].Hooks[0].Command
		want := "pre"
		if ev != "PreToolUse" {
			want = "post"
		}
		if !strings.HasPrefix(cmd, runhook.AgentBoxPath+" permission-hook "+want+" --config ") || !strings.Contains(cmd, runhook.ConfigPath("fix-1")) {
			t.Errorf("hooks[%s] command = %q", ev, cmd)
		}
	}
	if strings.Index(spawn, "--settings") > strings.Index(spawn, "--allowedTools") {
		t.Error("--settings must come before the variadic --allowedTools")
	}
}

func TestStartBoxRun_NoCommandPolicyLeavesTheRunUnchanged(t *testing.T) {
	r := runPolicyReq(t, "none", &pb.StartBoxRunRequest{})
	if r.err != nil {
		t.Fatal(r.err)
	}
	_, spawn := r.spawn()
	if strings.Contains(spawn, "--settings") {
		t.Errorf("no policy, but hooks were installed:\n%s", spawn)
	}
	if i, _ := r.auditSetup(); i >= 0 {
		t.Error("no policy, but the audit sink was set up")
	}
}

func TestDaemonCapabilities_AdvertiseCommandPolicy(t *testing.T) {
	if !slices.Contains(daemonCapabilities(), DaemonCapBoxRunCommandPolicy) || DaemonCapBoxRunCommandPolicy != "box_run_command_policy" {
		t.Errorf("capabilities = %q", daemonCapabilities())
	}
}

// configFromSetup runs the setup script's config write through a real shell
// against a temp directory and decodes what it wrote.
func configFromSetup(t *testing.T, setup string) runhook.Config {
	t.Helper()
	const marker = "printf '%s' "
	i := strings.Index(setup, marker)
	if i < 0 {
		t.Fatalf("no config write in setup:\n%s", setup)
	}
	line := setup[i:]
	line = line[:strings.Index(line, " > ")]
	out, err := exec.Command("sh", "-c", line).Output()
	if err != nil {
		t.Fatalf("config write: %v", err)
	}
	var cfg runhook.Config
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("config is not JSON: %v\n%s", err, out)
	}
	return cfg
}

type testHookSettings struct {
	Hooks map[string][]struct {
		Matcher string `json:"matcher"`
		Hooks   []struct {
			Type    string `json:"type"`
			Command string `json:"command"`
		} `json:"hooks"`
	} `json:"hooks"`
}

// settingsFromSpawn finds the --settings value as the shell would pass it:
// the run command is one single-quoted word of the spawn script's
// `setsid sh -c`, and the value one single-quoted word inside that.
func settingsFromSpawn(t *testing.T, spawn string) testHookSettings {
	t.Helper()
	lead := "setsid sh -c "
	i := strings.Index(spawn, lead)
	if i < 0 {
		lead = " --command "
		i = strings.Index(spawn, lead)
	}
	if i < 0 {
		t.Fatalf("no setsid or supervisor line in spawn:\n%s", spawn)
	}
	inner := shPrint(t, firstShellWord(spawn[i+len(lead):]))
	j := strings.Index(inner, "--settings ")
	if j < 0 {
		t.Fatalf("no --settings in the run command:\n%s", inner)
	}
	val := shPrint(t, firstShellWord(inner[j+len("--settings "):]))
	var s testHookSettings
	if err := json.Unmarshal([]byte(val), &s); err != nil {
		t.Fatalf("settings are not JSON: %v\n%s", err, val)
	}
	return s
}

func shPrint(t *testing.T, word string) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", "printf '%s' "+word).Output()
	if err != nil {
		t.Fatalf("unquote %q: %v", word, err)
	}
	return string(out)
}

// firstShellWord returns the leading shell word of s (quoting kept), up to the
// first unquoted blank.
func firstShellWord(s string) string {
	inQ := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'':
			inQ = !inQ
		case c == '\\' && !inQ:
			i++
		case (c == ' ' || c == '\n') && !inQ:
			return s[:i]
		}
	}
	return s
}

// Command mode (#3322) with a command policy goes through the same decision,
// sink and events as an engine run (#3582): the root sink starts first, the
// command is written into the root-owned configuration, and the run executes
// the root-owned agent-box's `permission-hook command` under the timeout, never
// the caller's text directly.
func TestStartBoxRun_CommandMode_CommandPolicyRoutesThroughTheHook(t *testing.T) {
	const text = "make lint && go test ./..."
	req := &pb.StartBoxRunRequest{
		RunName:        "cmd-1",
		Command:        text,
		TimeoutSeconds: 120,
		CommandPolicy:  withPolicy("make lint"),
		Approval:       &pb.AgentRunApproval{ApprovalId: "appr-2", ApproverId: "user-9"},
	}
	r := runPolicyReq(t, "build_tools", req)
	if r.err != nil {
		t.Fatal(r.err)
	}
	si, spawn := r.spawn()
	ai, setup := r.auditSetup()
	if si < 0 || ai < 0 {
		t.Fatalf("spawn at %d, audit setup at %d: both must run", si, ai)
	}
	if ai > si {
		t.Error("the sink must be running before the command is spawned")
	}
	cfg := configFromSetup(t, setup)
	if cfg.Command != text || cfg.RunName != "cmd-1" || !slices.Equal(cfg.Allow, []string{"make lint"}) {
		t.Errorf("config = %+v, want the command, run name and allowlist", cfg)
	}
	if cfg.Approval == nil || cfg.Approval.ID != "appr-2" {
		t.Errorf("config approval = %+v", cfg.Approval)
	}
	p, _ := boxRunPolicyFor("build_tools")
	if !slices.Equal(cfg.LevelAllowed, p.Allowed) || !slices.Equal(cfg.LevelDenied, p.Denied) {
		t.Error("config level rules differ from the level's policy")
	}
	for _, want := range []string{"timeout -k 5 120 ", runhook.AgentBoxPath, "permission-hook command --config", runhook.ConfigPath("cmd-1")} {
		if !strings.Contains(spawn, want) {
			t.Errorf("spawn lacks %q:\n%s", want, spawn)
		}
	}
	if strings.Contains(spawn, "go test") {
		t.Errorf("the caller's text reached the spawn instead of going through the hook:\n%s", spawn)
	}
}

// The policy needs the level's rules and the unprivileged run user in command
// mode too; a box without a recorded level is refused before anything changes.
func TestStartBoxRun_CommandMode_CommandPolicyRequiresARecordedLevel(t *testing.T) {
	r := runPolicyReq(t, "", &pb.StartBoxRunRequest{Command: "make lint", CommandPolicy: withPolicy("make lint")})
	if status.Code(r.err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", r.err)
	}
	for _, c := range r.calls {
		for _, m := range []string{"useradd", "mkdir", "chmod", "setsid", runhook.AuditDir} {
			if strings.Contains(c.script, m) {
				t.Errorf("refused run mutated the box (%q):\n%s", m, c.script)
			}
		}
	}
}

// The command mode the policy decides is the configured text, exactly: an
// allowlist refusal there ends the run with a typed reason and a BLOCKED event
// (see runhook.TestRunCommand_RefusalEndsTheRunWithTypedReasonAndBlockedEvent);
// here the daemon's configuration is fed to the same decision.
func TestStartBoxRun_CommandMode_RefusedCommandIsDecidedLikeAnEngineCommand(t *testing.T) {
	r := runPolicyReq(t, "none", &pb.StartBoxRunRequest{Command: "make deploy", CommandPolicy: withPolicy("make lint")})
	if r.err != nil {
		t.Fatal(r.err)
	}
	_, setup := r.auditSetup()
	cfg := configFromSetup(t, setup)
	d := runhook.Decide(cfg, cfg.Command)
	if d.Verdict != runhook.VerdictDeny || d.CloseReason != pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_NOT_ALLOWED {
		t.Errorf("decision = %+v, want a NOT_ALLOWED refusal", d)
	}
}

// FULL_SUDO: the allowlist and the hooks are installed and decide exactly as
// at any other level. They are advisory there (the run user can become root),
// which the docs say; this pins that they are not silently skipped.
func TestStartBoxRun_CommandPolicy_AppliesAtFullSudo(t *testing.T) {
	for name, req := range map[string]*pb.StartBoxRunRequest{
		"engine run":  {RunName: "fs-1", CommandPolicy: withPolicy("make lint")},
		"command run": {RunName: "fs-2", Command: "make lint", CommandPolicy: withPolicy("make lint")},
	} {
		t.Run(name, func(t *testing.T) {
			r := runPolicyReq(t, "full_sudo", req)
			if r.err != nil {
				t.Fatal(r.err)
			}
			si, spawn := r.spawn()
			ai, setup := r.auditSetup()
			if si < 0 || ai < 0 || ai > si {
				t.Fatalf("spawn at %d, audit setup at %d: the sink must start first", si, ai)
			}
			if req.Command == "" {
				if s := settingsFromSpawn(t, spawn); len(s.Hooks["PreToolUse"]) != 1 || len(s.Hooks["PostToolUse"]) != 1 {
					t.Errorf("hooks not installed at full_sudo: %+v", s)
				}
			} else if !strings.Contains(spawn, "permission-hook command") {
				t.Errorf("command not routed through the hook at full_sudo:\n%s", spawn)
			}
			cfg := configFromSetup(t, setup)
			p, _ := boxRunPolicyFor("full_sudo")
			if !slices.Equal(cfg.LevelAllowed, p.Allowed) {
				t.Error("config level rules are not full_sudo's")
			}
			for cmd, want := range map[string]pb.AgentCommandCloseReason{
				"git push origin main":           pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_HARD_DENY,
				"curl https://example.invalid/x": pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_HARD_DENY,
				"python3 deploy.py":              pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_NOT_ALLOWED,
			} {
				if d := runhook.Decide(cfg, cmd); d.Verdict != runhook.VerdictDeny || d.CloseReason != want {
					t.Errorf("%q at full_sudo: %+v, want %s", cmd, d, want)
				}
			}
			if d := runhook.Decide(cfg, "make lint"); d.Verdict == runhook.VerdictDeny {
				t.Errorf("allowlisted command refused at full_sudo: %+v", d)
			}
		})
	}
}

// The sink reads the run's end from its exit status, and decides between
// ENGINE_REFUSED and INTERRUPTED on it. The run user owns the run directory,
// so that status must not come from there: under a command policy the run is
// launched by the root-owned supervisor, which is the run's parent and writes
// the status to a root-only directory the setup creates, as it does the events
// directory. The run user never spawns the run itself.
func TestStartBoxRun_CommandPolicy_ExitStatusIsRecordedByRootNotTheRunUser(t *testing.T) {
	for name, req := range map[string]*pb.StartBoxRunRequest{
		"engine run":  {RunName: "ex-1", CommandPolicy: withPolicy("make lint")},
		"command run": {RunName: "ex-2", Command: "make lint", CommandPolicy: withPolicy("make lint")},
	} {
		t.Run(name, func(t *testing.T) {
			r := runPolicyReq(t, "none", req)
			if r.err != nil {
				t.Fatal(r.err)
			}
			ai, setup := r.auditSetup()
			cfg := configFromSetup(t, setup)
			if cfg.ExitPath != runhook.ExitPath(req.RunName) || !strings.HasPrefix(cfg.ExitPath, runhook.AuditDir+"/exit/") {
				t.Errorf("config exit_path = %q, want %q", cfg.ExitPath, runhook.ExitPath(req.RunName))
			}
			for _, want := range []string{
				`chown root:root "$a" "$a/bin" "$a/s" "$a/events" "$a/exit"`,
				`chmod 0700 "$a/events" "$a/exit"`,
				"rm -f '" + runhook.ExitPath(req.RunName) + "'",
				runhook.SuperviseUsage,
			} {
				if !strings.Contains(setup, want) {
					t.Errorf("audit setup lacks %q:\n%s", want, setup)
				}
			}

			li, launch := -1, ""
			prep := -1
			for i, c := range r.calls {
				switch {
				case c.root && strings.Contains(c.script, "run-supervise --config '"):
					li, launch = i, c.script
				case !c.root && strings.Contains(c.script, "__cx=$?"):
					t.Errorf("the run user spawned the run itself, so it would write the status the sink reads:\n%s", c.script)
				case !c.root && strings.Contains(c.script, ".log") && strings.Contains(c.script, "rm -f") && prep < 0:
					prep = i
				}
			}
			if li < 0 {
				t.Fatal("no root supervisor launch")
			}
			if ai > li || prep < 0 || prep > li {
				t.Errorf("setup at %d, prepare at %d, launch at %d: setup and prepare come first", ai, prep, li)
			}
			for _, want := range []string{
				runhook.AgentBoxPath + "' run-supervise --config '" + runhook.ConfigPath(req.RunName) + "'",
				"--user '" + boxRunUnprivilegedUser + "'",
				runhook.LaunchPath(req.RunName),
			} {
				if !strings.Contains(launch, want) {
					t.Errorf("launch lacks %q:\n%s", want, launch)
				}
			}
			if out, err := exec.Command("sh", "-n", "-c", launch).CombinedOutput(); err != nil {
				t.Errorf("launch does not parse: %v\n%s", err, out)
			}
		})
	}
	// Without a policy nothing changes: the run user spawns its run.
	r := runPolicyReq(t, "none", &pb.StartBoxRunRequest{})
	for _, c := range r.calls {
		if strings.Contains(c.script, "run-supervise") {
			t.Errorf("no policy, but the supervisor was used:\n%s", c.script)
		}
	}
}
