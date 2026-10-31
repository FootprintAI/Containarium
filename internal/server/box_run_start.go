package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/agentbox"
	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/coderun/engine"
	corecontainer "github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/toolchain"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// StartBoxRun (#2193): the daemon-driven counterpart to `containarium code
// run` for a caller with no SSH client. It root-execs a shell script on the
// box via the SAME mgr.ExecWithExitCode path ListBoxRuns/TailBoxRunLog
// already use — no SSH, no agent-box RPC — that replicates
// spawnBackgroundProcess's on-disk contract (atomic temp+rename RunRecord
// JSON, setsid-detached child, child-written .exit sidecar), so the existing
// readers see a daemon-started run exactly like a `code run`-started one.
//
// Unlike List/Tail (which only ever READ, as root, files the box's user
// owns), starting a run has to WRITE as that user: the spawned engine process
// needs that user's $HOME to find its own credentials, and the record/log it
// creates need to end up owned the same way an SSH-driven `code run` leaves
// them. So every write here goes through boxRunStartExecFn, which wraps the
// script in `su - <username> -c` — never boxRunExecFn's plain root exec.

// boxRunStartFunc is StartBoxRun's own exec seam: production wraps the
// container manager AND drops privilege to username via `su -`; tests fake
// it directly (ignoring username — a test sandbox has no real box user to
// drop into).
type boxRunStartFunc func(box, username, script string) (string, error)

// Stable reason for a BUILD_TOOLS refusal when the host release is absent.
const BoxRunViolationHostManagedToolchainMissing = "HOST_MANAGED_TOOLCHAIN_MISSING"

// boxRunToolchainRefusal preserves the existing FailedPrecondition behavior
// for every ensure failure, adding a typed violation only for the explicit
// host-release-missing condition.
func boxRunToolchainRefusal(err error) error {
	msg := fmt.Sprintf("managed toolchain mount %s: %v", toolchain.HostRoot, err)
	st := status.New(codes.FailedPrecondition, msg)
	if err == nil || !errors.Is(err, corecontainer.ErrManagedToolchainHostMissing) {
		return st.Err()
	}
	detailed, detailErr := st.WithDetails(&errdetails.PreconditionFailure{
		Violations: []*errdetails.PreconditionFailure_Violation{{Type: BoxRunViolationHostManagedToolchainMissing, Subject: toolchain.HostRoot, Description: msg}},
	})
	if detailErr == nil {
		st = detailed
	}
	return st.Err()
}

// boxRunStartExecFn returns the exec seam: the injected fake, else the
// container manager wrapped with `su - <username> -c`.
func (s *ContainerServer) boxRunStartExecFn() boxRunStartFunc {
	if s.boxRunStartExec != nil {
		return s.boxRunStartExec
	}
	if s.manager == nil {
		return nil
	}
	mgr := s.manager
	return func(box, username, script string) (string, error) {
		wrapped := "su - " + shellSingleQuote(username) + " -c " + shellSingleQuote(script)
		out, stderr, code, err := mgr.ExecWithExitCode(box, []string{"sh", "-c", wrapped})
		if err != nil {
			return "", err
		}
		if code != 0 {
			return "", fmt.Errorf("exit %d: %s", code, strings.TrimSpace(stderr))
		}
		return out, nil
	}
}

// boxRunHomeAndConfigScript prints the box user's $HOME on its own first
// line, then code.json's raw content (if it exists), if any — one round trip
// for both, since StartBoxRun always needs $HOME anyway (it's the run's cwd,
// and the base of every session-discovery path).
func boxRunHomeAndConfigScript() string {
	return `printf '%s\n' "$HOME"
cat "$HOME/.containarium/code.json" 2>/dev/null || true
`
}

// resolveBoxRunConfig reads $HOME and code.json off the box (as the box's own
// user) and resolves the engine+credential choice the box was installed
// with. A box with no code.json (every box installed before #1727) falls
// back to the same default `code run` does: Claude Code + a tenant secret —
// see readBoxCodeConfig's identical contract in internal/cmd/code_run_engine.go.
func resolveBoxRunConfig(exec boxRunStartFunc, box, username string) (home string, cfg *engine.CodeConfig, err error) {
	out, err := exec(box, username, boxRunHomeAndConfigScript())
	if err != nil {
		return "", nil, status.Errorf(codes.Unavailable, "read %s's $HOME/code.json on %q: %v", username, box, err)
	}
	home, rest, _ := strings.Cut(out, "\n")
	home = strings.TrimSpace(home)
	if home == "" {
		return "", nil, status.Errorf(codes.Unavailable, "could not resolve $HOME for %q on %q", username, box)
	}
	blob := strings.TrimSpace(rest)
	if blob == "" {
		return home, &engine.CodeConfig{
			Version:    engine.CodeConfigVersion,
			Engine:     engine.DefaultName,
			Credential: engine.DefaultKind,
		}, nil
	}
	cfg, perr := engine.ParseCodeConfig([]byte(blob))
	if perr != nil {
		return "", nil, status.Errorf(codes.FailedPrecondition, "%s on %q: %v", engine.CodeConfigPath, box, perr)
	}
	return home, cfg, nil
}

// boxRunSpawn is everything boxRunSpawnScript needs to render one run's
// launch script.
type boxRunSpawn struct {
	dir, name, command, home string
	// prelaunch runs before the engine is launched (the session-directory
	// snapshot a fresh run's discovery compares against). Empty for none.
	prelaunch string
	// sessionTrailer is appended verbatim after the pid/boot line: either a
	// literal sidecar write (a resumed run, whose session id is known from
	// the request) or the backgrounded discovery poll (a fresh run). Safe to
	// run unconditionally: a literal write is instant, the poll detaches.
	sessionTrailer string
	// structured keeps stderr in <name>.stderr.log so <name>.log is exactly
	// the engine's JSON result object, and reads the session id out of that
	// object when the engine exits (StartBoxRunRequest.structured_output).
	structured bool
}

// boxRunSpawnScript builds the script that spawns the command detached
// (setsid, so it survives this exec call returning), replicating
// spawnBackgroundProcess's shape: stdout+stderr to the run's log, the child
// itself writing its own exit status to <name>.exit on completion (atomic
// temp+rename), since nothing here stays alive to reap it. Prints "<pid>
// <boot_id>" as its one line of stdout.
func boxRunSpawnScript(sp boxRunSpawn) string {
	q := shellSingleQuote
	dir, name := sp.dir, sp.name
	logPath := dir + "/" + name + ".log"
	stderrPath := dir + "/" + name + ".stderr.log"
	exitPath := dir + "/" + name + ".exit"
	sessionPath := dir + "/" + name + ".session"
	toolsPath := dir + "/" + name + ".tools"
	toolsTmp := toolsPath + ".tmp"

	redirect := ">" + q(logPath) + " 2>&1"
	if sp.structured {
		redirect = ">" + q(logPath) + " 2>" + q(stderrPath)
		// The result object carries the conversation's own session_id; the
		// daemon decodes it (top-level key only) when listing the run.
	}
	// The toolchain report (#2954): a probe before the engine and one after it, in the
	// run's own shell, so it is written whatever the engine's exit status and costs no
	// model tokens. It lands BEFORE the exit sidecar, so a reader that sees the run
	// finished also sees its tools.
	inner := boxRunToolsPreProbe(toolsTmp) + "( " + sp.command + " ) " + redirect + "; __cx=$?; " +
		boxRunToolsPostProbe(toolsTmp, toolsPath) +
		"printf '%s %s' \"$__cx\" \"$(date -u +%s)\" > " + q(exitPath+".tmp") + " 2>/dev/null && " +
		"mv -f " + q(exitPath+".tmp") + " " + q(exitPath) + "; exit $__cx"

	script := "set -e\n" +
		"d=" + q(dir) + "\n" +
		"mkdir -p \"$d\"\n" +
		": > " + q(logPath) + "\n" +
		"chmod 600 " + q(logPath) + " 2>/dev/null || true\n"
	if sp.structured {
		script += ": > " + q(stderrPath) + "\n" +
			"chmod 600 " + q(stderrPath) + " 2>/dev/null || true\n"
	}
	script += "rm -f " + q(exitPath) + " " + q(sessionPath) + " " + q(sessionPath+".snap") + " " + q(toolsPath) + " " + q(toolsTmp) + " " + q(toolsTmp+".e.") + "*\n" +
		"cd " + q(sp.home) + " 2>/dev/null || true\n"
	if sp.prelaunch != "" {
		script += sp.prelaunch + "\n"
	}
	script += "setsid sh -c " + q(inner) + " </dev/null >/dev/null 2>&1 &\n" +
		"pid=$!\n" +
		"disown 2>/dev/null || true\n" +
		"boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)\n" +
		"printf '%s %s\\n' \"$pid\" \"$boot\"\n"
	if sp.sessionTrailer != "" {
		script += sp.sessionTrailer + "\n"
	}
	return script
}

// sessionSidecarWriteCommand atomically writes id as name's session sidecar —
// used when the session id is already known (a resumed run), so ListBoxRuns
// reports it immediately instead of waiting on discovery for a value that was
// never ambiguous.
func sessionSidecarWriteCommand(dir, name, id string) string {
	q := shellSingleQuote
	path := dir + "/" + name + ".session"
	return "printf '%s' " + q(id) + " > " + q(path+".tmp") + " 2>/dev/null && mv -f " + q(path+".tmp") + " " + q(path)
}

// boxRunWriteRecordScript atomically writes recordJSON as name's run record,
// base64-encoded over the wire so arbitrary JSON content (quotes, backslashes,
// unicode in a caller-supplied prompt) never has to be re-escaped for a shell
// string — the same reason this file's readers (box_run_log.go) move every
// record and sidecar across the exec boundary as base64.
func boxRunWriteRecordScript(dir, name string, recordJSON []byte) string {
	q := shellSingleQuote
	path := dir + "/" + name + ".json"
	tmp := dir + "/." + name + ".start.tmp"
	b64 := base64.StdEncoding.EncodeToString(recordJSON)
	return "printf '%s' " + q(b64) + " | base64 -d > " + q(tmp) + " && chmod 600 " + q(tmp) + " 2>/dev/null; mv -f " + q(tmp) + " " + q(path)
}

// boxRunRotateScript renames name's existing record/log/exit/session aside
// under the ".<startedAtUnix>" suffix, mirroring agentbox.rotateFinishedRun —
// a fresh run reusing this name must never silently truncate the previous
// run's output. Missing files are not an error: rotation's job is "don't
// destroy what's there," not "guarantee it exists."
func boxRunRotateScript(dir, name string, startedAtUnix int64) string {
	q := shellSingleQuote
	suffix := "." + strconv.FormatInt(startedAtUnix, 10)
	var b strings.Builder
	for _, ext := range []string{"json", "log", "stderr.log", "exit", "session", "session.snap", "tools"} {
		from := q(dir + "/" + name + "." + ext)
		to := q(dir + "/" + name + suffix + "." + ext)
		fmt.Fprintf(&b, "[ -e %s ] && mv -f %s %s 2>/dev/null; ", from, from, to)
	}
	b.WriteString("true\n")
	return b.String()
}

// checkBoxRunCollision looks for an existing run under name via the SAME
// listing ListBoxRuns uses, so "is a previous run for this name still going?"
// is answered with the identical outcome logic a caller would see from
// `code runs`. running="" means no collision; rotate=true means a finished
// run under this name must be rotated aside before a fresh one starts.
func checkBoxRunCollision(exec boxScriptFunc, box, dir, name string) (collision *pb.BoxRun, rotate bool, err error) {
	out, err := exec(box, boxRunListScript(dir))
	if err != nil {
		return nil, false, status.Errorf(codes.Unavailable, "list existing runs on %q: %v", box, err)
	}
	for _, r := range parseBoxRunList(out, dir) {
		if r.GetRunName() != name {
			continue
		}
		if r.GetOutcome() == pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED {
			return r, true, nil
		}
		return r, false, nil
	}
	return nil, false, nil
}

// boxRunLockKey is s.boxRunLocks' key for a given (box, name) pair.
func boxRunLockKey(box, name string) string {
	return box + ":" + name
}

// boxRunLockFor returns s.boxRunLocks' *sync.Mutex for key, creating it on
// first use (#2260 review, "should fix": two concurrent StartBoxRun calls
// for the same not-yet-existing name could both pass checkBoxRunCollision,
// then race on the log truncate and the atomic record write — corrupting
// the log and orphaning a PID with no record naming it). Locking around the
// whole check-then-write span per (box, name) makes the second concurrent
// caller either see the first's collision (clean FailedPrecondition) or
// proceed only after the first has fully finished writing its record.
func (s *ContainerServer) boxRunLockFor(key string) *sync.Mutex {
	v, _ := s.boxRunLocks.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// StartBoxRun starts (or resumes) a coding-agent run on a box with no SSH
// client needed (#2193).
func (s *ContainerServer) StartBoxRun(ctx context.Context, req *pb.StartBoxRunRequest) (*pb.StartBoxRunResponse, error) {
	if err := validateBoxRunOwner(req.GetUsername()); err != nil {
		return nil, err
	}
	// Command mode (#3322): a shell command instead of an engine prompt. The two
	// are exclusive, and so is everything that only means something to an engine.
	commandMode := strings.TrimSpace(req.GetCommand()) != ""
	if !commandMode && strings.TrimSpace(req.GetPrompt()) == "" {
		return nil, status.Error(codes.InvalidArgument, "prompt is required (or command, to run a shell command instead of an engine)")
	}
	if commandMode && (req.GetPrompt() != "" || req.GetSessionId() != "" || req.GetContinueSession() || req.GetStructuredOutput() || req.GetModel() != "") {
		return nil, status.Error(codes.InvalidArgument, "command is mutually exclusive with prompt, session_id, continue_session, structured_output and model")
	}
	if req.GetTimeoutSeconds() != 0 && !commandMode {
		return nil, status.Error(codes.InvalidArgument, "timeout_seconds applies to command only")
	}
	if req.GetTimeoutSeconds() < 0 || req.GetTimeoutSeconds() > coderun.MaxCommandTimeoutSeconds {
		return nil, status.Errorf(codes.InvalidArgument, "timeout_seconds must be between 0 and %d", coderun.MaxCommandTimeoutSeconds)
	}
	if req.GetSessionId() != "" && req.GetContinueSession() {
		return nil, status.Error(codes.InvalidArgument, "session_id and continue_session are mutually exclusive")
	}
	if req.GetSessionId() != "" && !validRunPathID(req.GetSessionId()) {
		return nil, status.Errorf(codes.InvalidArgument, "session_id must match %s and not be . or ..", runIDPattern.String())
	}
	if req.GetRunName() != "" && !validRunPathID(req.GetRunName()) {
		return nil, status.Errorf(codes.InvalidArgument, "run_name must match %s and not be . or ..", runIDPattern.String())
	}
	if req.GetRunName() != "" && boxRunNameCollidesWithDerivedFile(req.GetRunName()) {
		return nil, status.Error(codes.InvalidArgument,
			"run_name must not end in \".stderr\" or in \".<digits>\" (those collide with a run's derived files and rotated-aside runs)")
	}
	if req.GetModel() != "" && !validBoxRunModel(req.GetModel()) {
		return nil, status.Errorf(codes.InvalidArgument, "model must match %s", boxRunModelPattern.String())
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}

	listExec := s.boxRunExecFn()
	startExec := s.boxRunStartExecFn()
	if listExec == nil || startExec == nil {
		return nil, status.Error(codes.Unavailable, "no container backend to start a run on")
	}

	// An explicit run_name wins. Otherwise #2193's accepted default: session_id
	// doubles as run_name when resuming via --session; a fresh run (or one
	// resuming "whatever's most recent" via continue_session) keeps the shared
	// default name `code run` itself uses.
	name := req.GetRunName()
	if name == "" {
		name = req.GetSessionId()
	}
	if name == "" {
		name = coderun.DefaultRunName
	}

	box := req.GetUsername() + "-container"
	dir := s.boxRunDir()

	// #2260 review (should-fix): serialize the whole check-then-write span
	// per (box, name) so two concurrent calls for the same new name can't
	// both pass the collision check below and then race on the log
	// truncate/record write further down. Acquired before the FIRST
	// filesystem read of this span (the collision check) so the second
	// caller sees a fully-finished first call, not a half-done one.
	lock := s.boxRunLockFor(boxRunLockKey(box, name))
	lock.Lock()
	defer lock.Unlock()

	collision, rotate, err := checkBoxRunCollision(listExec, box, dir, name)
	if err != nil {
		return nil, err
	}
	if collision != nil && !rotate {
		return nil, status.Errorf(codes.FailedPrecondition,
			"run %q on %q is already %s — no queueing; pick a different session, or wait for it to finish",
			name, req.GetUsername(), strings.ToLower(strings.TrimPrefix(collision.GetOutcome().String(), "BOX_RUN_OUTCOME_")))
	}

	// #2260 review (blocking): every precondition/validation check — gateway
	// credential, malformed code.json, anything else that can still fail —
	// MUST run before the rotate-aside below, which is a filesystem
	// mutation. Resolving config here is read-only (just $HOME + code.json),
	// so moving it ahead of the rotate costs nothing and means a refusal
	// from here on leaves a colliding finished run's files exactly where
	// they were, still discoverable under their original name.
	home, cfg, err := resolveBoxRunConfig(startExec, box, req.GetUsername())
	if err != nil {
		return nil, err
	}
	if commandMode {
		return s.startBoxRunCommand(ctx, req, box, dir, name, home, listExec, startExec, collision, rotate)
	}
	if cfg.Credential == engine.KindGateway {
		// #2193 scope boundary (documented in the PR, not a silent gap): a
		// gateway-credentialed box needs the daemon to mint its own run
		// token in-process, which this change does not add. `code run` over
		// SSH still works on such a box today; only the no-SSH-client path
		// is unavailable for it.
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s on %q selects the gateway credential, which StartBoxRun does not support yet — use `containarium code run %s` instead",
			engine.CodeConfigPath, req.GetUsername(), req.GetUsername())
	}
	eng, err := cfg.EngineFor()
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%s on %q: %v", engine.CodeConfigPath, req.GetUsername(), err)
	}

	if req.GetStructuredOutput() && eng.Name() != engine.NameClaude {
		return nil, status.Errorf(codes.FailedPrecondition,
			"structured_output is only supported for the %s engine; %s on %q selects %s",
			engine.NameClaude, engine.CodeConfigPath, req.GetUsername(), eng.Name())
	}

	if req.GetModel() != "" && eng.Name() != engine.NameClaude {
		return nil, status.Errorf(codes.FailedPrecondition,
			"model is only supported for the %s engine; %s on %q selects %s",
			engine.NameClaude, engine.CodeConfigPath, req.GetUsername(), eng.Name())
	}

	// A box with a recorded tool-access level runs platform-started work as a
	// dedicated unprivileged user (#2944, slice 1b); a box with none keeps the
	// owner's identity exactly as before. The level is read before anything is
	// mutated, and a read error refuses the run rather than demoting it.
	level, err := s.boxRunRecordedToolAccess(ctx, req.GetUsername())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read the tool-access level of %q: %v", req.GetUsername(), err)
	}
	runAs := req.GetUsername()
	// The level's policy is CLI flags on the run command, so it exists only for
	// the Claude Code engine; an unknown level or another engine is refused
	// before anything is mutated, never started without a policy.
	var policy boxRunPolicy
	if level != "" {
		if eng.Name() != engine.NameClaude {
			return nil, status.Errorf(codes.FailedPrecondition,
				"%q has a tool-access level recorded, which is only enforced for the %s engine; %s on %q selects %s",
				req.GetUsername(), engine.NameClaude, engine.CodeConfigPath, req.GetUsername(), eng.Name())
		}
		if policy, err = boxRunPolicyFor(level); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "%q: %v", req.GetUsername(), err)
		}
	}

	// Lazily attach the release to old boxes before rotating any previous run.
	// Only BUILD_TOOLS requires it; the other levels keep working on hosts
	// that have not installed a managed toolchain release.
	ensureTools := s.boxRunEnsureToolchain
	if ensureTools == nil && s.manager != nil {
		ensureTools = s.manager.EnsureManagedToolchains
	}
	if level == "build_tools" {
		if ensureTools == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "missing managed toolchain mount %s", toolchain.HostRoot)
		}
		if err := ensureTools(req.GetUsername()); err != nil {
			return nil, boxRunToolchainRefusal(err)
		}
	} else if ensureTools != nil {
		_ = ensureTools(req.GetUsername())
	}

	// The level and required mount are ready; now provision the run user.
	if level != "" {
		runHome, err := prepareUnprivilegedRun(listExec, box, dir, home, level)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "prepare the unprivileged run user on %q: %v", req.GetUsername(), err)
		}
		runAs, home = boxRunUnprivilegedUser, runHome

		// The run user must already hold a usable sign-in of its own. Checked
		// after provisioning (it needs the user and the CLI) and before anything
		// is rotated or spawned, so a refusal leaves every earlier run untouched.
		state, err := boxRunSignInState(startExec, box)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "check the run user's sign-in on %q: %v", req.GetUsername(), err)
		}
		if state != engine.CredentialStatusInteractive && state != engine.CredentialStatusAPIKey {
			return nil, boxRunSignInRefusal(box, state, runHome)
		}
	}

	// Only now does a finished prior run under this name get rotated aside. In
	// the unprivileged path the rotate runs as root: the finished run's files may
	// belong to the owner (a run from before a level was recorded), which the
	// run user could not rename in the sticky run directory.
	if rotate {
		rotateScript := boxRunRotateScript(dir, name, collision.GetStartedAt().AsTime().Unix())
		var err error
		if level != "" {
			_, err = listExec(box, rotateScript)
		} else {
			_, err = startExec(box, req.GetUsername(), rotateScript)
		}
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "rotate finished run %q on %q: %v", name, req.GetUsername(), err)
		}
	}

	command := eng.RunCommand(req.GetPrompt(), false, req.GetContinueSession(), req.GetSessionId())
	if req.GetStructuredOutput() {
		command += engine.ClaudeStructuredOutputFlag
	}

	if req.GetModel() != "" {
		// Validated above to a plain id; quoted anyway, as the prompt is.
		command += " --model " + coderun.ShellQuoteSingle(req.GetModel())
	}

	if level != "" {
		command += policy.commandFlags()
	}

	sp := boxRunSpawn{dir: dir, name: name, command: command, home: home, structured: req.GetStructuredOutput()}
	sidecar := dir + "/" + name + ".session"
	switch {
	case req.GetSessionId() != "":
		// Already known from the request — write it immediately rather than
		// rediscovering it.
		sp.sessionTrailer = sessionSidecarWriteCommand(dir, name, req.GetSessionId())
	case req.GetStructuredOutput():
		// The engine's JSON result reports its own session id when the run
		// ends (see boxRunSpawnScript); directory discovery is not needed.
	default:
		// A fresh run: snapshot the engine's session directory BEFORE the
		// launch, then poll for the one entry this run creates. Never the
		// newest pre-existing one (see engine/session_discovery.go).
		if pre, ok := engine.SessionDiscoveryPrepareCommand(eng.Name(), home, home, sidecar); ok {
			if cmd, ok := engine.SessionDiscoveryBackgroundCommand(eng.Name(), home, home, sidecar); ok {
				sp.prelaunch = pre
				sp.sessionTrailer = cmd
			}
		}
	}

	out, err := startExec(box, runAs, boxRunSpawnScript(sp))
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "start run %q on %q: %v", name, req.GetUsername(), err)
	}
	pidStr, boot, found := strings.Cut(strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]), " ")
	if !found {
		return nil, status.Errorf(codes.Internal, "unexpected spawn output %q", out)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(pidStr))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unexpected spawn pid %q", pidStr)
	}

	startedAt := time.Now().UTC()
	record := agentbox.RunRecord{
		Version:     agentbox.RunRecordVersion,
		Name:        name,
		PID:         pid,
		BootID:      strings.TrimSpace(boot),
		Command:     command,
		Cwd:         home,
		CaptureMode: agentbox.CaptureCombined,
		LogPath:     dir + "/" + name + ".log",
		StartedAt:   startedAt,
		Model:       req.GetModel(),
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal run record: %v", err)
	}
	if _, err := startExec(box, runAs, boxRunWriteRecordScript(dir, name, recordJSON)); err != nil {
		return nil, status.Errorf(codes.Unavailable, "persist run record for %q on %q: %v", name, req.GetUsername(), err)
	}

	run := boxRunProto(name, dir, record, agentbox.RunOutcomeRunning)
	if req.GetSessionId() != "" {
		run.SessionId = req.GetSessionId()
	}
	return &pb.StartBoxRunResponse{Run: run}, nil
}

// startBoxRunCommand is StartBoxRun's command mode (#3322): the same run
// directory, record, rotation, identity and tool-access handling as an engine
// run, with a shell command under a timeout in the engine's place. Nothing
// engine-specific happens: no code.json engine is resolved, no gateway token,
// no sign-in probe (nothing is signed in), no session discovery. The caller has
// validated the request and holds the (box, name) lock.
func (s *ContainerServer) startBoxRunCommand(ctx context.Context, req *pb.StartBoxRunRequest, box, dir, name, home string, listExec boxScriptFunc, startExec boxRunStartFunc, collision *pb.BoxRun, rotate bool) (*pb.StartBoxRunResponse, error) {
	level, err := s.boxRunRecordedToolAccess(ctx, req.GetUsername())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read the tool-access level of %q: %v", req.GetUsername(), err)
	}
	if level != "" {
		if _, err := boxRunPolicyFor(level); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "%q: %v", req.GetUsername(), err)
		}
	}
	ensureTools := s.boxRunEnsureToolchain
	if ensureTools == nil && s.manager != nil {
		ensureTools = s.manager.EnsureManagedToolchains
	}
	if level == "build_tools" {
		if ensureTools == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "missing managed toolchain mount %s", toolchain.HostRoot)
		}
		if err := ensureTools(req.GetUsername()); err != nil {
			return nil, boxRunToolchainRefusal(err)
		}
	} else if ensureTools != nil {
		_ = ensureTools(req.GetUsername())
	}
	runAs := req.GetUsername()
	if level != "" {
		// The run user, its sudo grant for the level and its staged home, as for an
		// engine run; the engine sign-in is not checked, because no engine starts.
		runHome, err := prepareUnprivilegedRun(listExec, box, dir, home, level)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "prepare the unprivileged run user on %q: %v", req.GetUsername(), err)
		}
		runAs, home = boxRunUnprivilegedUser, runHome
	}
	if rotate {
		rotateScript := boxRunRotateScript(dir, name, collision.GetStartedAt().AsTime().Unix())
		var err error
		if level != "" {
			_, err = listExec(box, rotateScript)
		} else {
			_, err = startExec(box, req.GetUsername(), rotateScript)
		}
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "rotate finished run %q on %q: %v", name, req.GetUsername(), err)
		}
	}

	command := coderun.BuildShellCommand(req.GetCommand(), int(req.GetTimeoutSeconds()))
	out, err := startExec(box, runAs, boxRunSpawnScript(boxRunSpawn{dir: dir, name: name, command: command, home: home}))
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "start run %q on %q: %v", name, req.GetUsername(), err)
	}
	pidStr, boot, found := strings.Cut(strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]), " ")
	if !found {
		return nil, status.Errorf(codes.Internal, "unexpected spawn output %q", out)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(pidStr))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unexpected spawn pid %q", pidStr)
	}
	record := agentbox.RunRecord{
		Version:     agentbox.RunRecordVersion,
		Name:        name,
		PID:         pid,
		BootID:      strings.TrimSpace(boot),
		Command:     command,
		Cwd:         home,
		CaptureMode: agentbox.CaptureCombined,
		LogPath:     dir + "/" + name + ".log",
		StartedAt:   time.Now().UTC(),
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal run record: %v", err)
	}
	if _, err := startExec(box, runAs, boxRunWriteRecordScript(dir, name, recordJSON)); err != nil {
		return nil, status.Errorf(codes.Unavailable, "persist run record for %q on %q: %v", name, req.GetUsername(), err)
	}
	return &pb.StartBoxRunResponse{Run: boxRunProto(name, dir, record, agentbox.RunOutcomeRunning)}, nil
}

// Daemon capability names advertised in SystemInfo.capabilities. A client
// checks for a name before sending the request field it gates (the REST mux
// rejects unknown JSON fields, so an older daemon would fail the whole call).
// Names are only ever added.
const (
	// DaemonCapBoxRunName: StartBoxRunRequest.run_name.
	DaemonCapBoxRunName = "box_run_name"
	// DaemonCapBoxRunStructuredOutput: StartBoxRunRequest.structured_output.
	DaemonCapBoxRunStructuredOutput = "box_run_structured_output"
	// DaemonCapBoxRunModel: StartBoxRunRequest.model and BoxRun.model (#3259).
	DaemonCapBoxRunModel = "box_run_model"
	// DaemonCapBoxRunCommand: StartBoxRunRequest.command and timeout_seconds (#3322).
	DaemonCapBoxRunCommand = "box_run_command"
)

// daemonCapabilities is the list GetSystemInfo reports.
func daemonCapabilities() []string {
	return []string{DaemonCapBoxRunName, DaemonCapBoxRunStructuredOutput, DaemonCapBoxRunModel, DaemonCapBoxRunCommand}
}

// boxRunNameCollidesWithDerivedFile reports whether name would alias a file or
// run the daemon derives from another run: "<n>.stderr" makes "<n>.stderr.json"
// / ".log" look like <n>'s stderr log, and "<n>.<digits>" is the rotation
// suffix of a finished run named <n>.
func boxRunNameCollidesWithDerivedFile(name string) bool {
	if strings.HasSuffix(name, ".stderr") {
		return true
	}
	i := strings.LastIndex(name, ".")
	if i < 0 || i == len(name)-1 {
		return false
	}
	for _, c := range name[i+1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// prepareUnprivilegedRun makes the box ready for an unprivileged run (all as
// root, all idempotent): the run user exists, the run directory is writable by
// it, and its home holds a fresh staged copy of what the run reads. Returns the
// run user's home.
func prepareUnprivilegedRun(rootExec func(box, script string) (string, error), box, dir, ownerHome, level string) (string, error) {
	out, err := rootExec(box, boxRunProvisionScript())
	if err != nil {
		return "", fmt.Errorf("provision %s: %w", boxRunUnprivilegedUser, err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	runHome := strings.TrimSpace(lines[len(lines)-1])
	if !validHomePath(runHome) {
		return "", fmt.Errorf("unexpected home %q for %s", runHome, boxRunUnprivilegedUser)
	}
	if _, err := rootExec(box, boxRunSudoersScript(level)); err != nil {
		return "", fmt.Errorf("apply the sudo grant for level %q: %w", level, err)
	}
	if _, err := rootExec(box, boxRunDirScript(dir)); err != nil {
		return "", fmt.Errorf("prepare run directory: %w", err)
	}
	stage, err := boxRunStageScript(ownerHome, runHome)
	if err != nil {
		return "", err
	}
	if _, err := rootExec(box, stage); err != nil {
		return "", fmt.Errorf("stage the run user's home: %w", err)
	}
	return runHome, nil
}

// boxRunModelPattern bounds a model id. The id is opaque to the API, but it ends
// up in a shell command, so only the characters real ids use are allowed, and it
// cannot start with "-" (it would read as another flag).
var boxRunModelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/\[\]-]{0,127}$`)

func validBoxRunModel(id string) bool { return boxRunModelPattern.MatchString(id) }
