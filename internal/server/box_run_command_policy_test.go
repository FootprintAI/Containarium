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

func (r policyReqRun) spawn() (int, string) {
	for i, c := range r.calls {
		if !c.root && strings.Contains(c.script, "setsid") {
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
			if strings.Contains(script, "useradd") {
				return "/srv/" + boxRunUnprivilegedUser + "\n", nil
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
		"policy with command mode":     {Command: "true", CommandPolicy: withPolicy("make lint")},
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
	const lead = "setsid sh -c "
	i := strings.Index(spawn, lead)
	if i < 0 {
		t.Fatalf("no setsid line in spawn:\n%s", spawn)
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
