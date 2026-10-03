package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/agentbox"
	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/coderun/engine"
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

// boxRunSpawnScript builds the script that spawns command detached (setsid,
// so it survives this exec call returning), replicating
// spawnBackgroundProcess's shape: stdout+stderr to the run's log, the child
// itself writing its own exit status to <name>.exit on completion (atomic
// temp+rename), since nothing here stays alive to reap it. Prints "<pid>
// <boot_id>" as its one line of stdout.
//
// sessionTrailer, when non-empty, is appended verbatim after the pid/boot
// line — either a literal sidecar write (a resumed run, whose session id is
// already known from the request) or a backgrounded discovery poll (a fresh
// run, #2193's SessionDiscoveryBackgroundCommand). Both are safe to run
// unconditionally: a literal write is instant, and the poll detaches itself.
func boxRunSpawnScript(dir, name, command, home, sessionTrailer string) string {
	q := shellSingleQuote
	logPath := dir + "/" + name + ".log"
	exitPath := dir + "/" + name + ".exit"
	sessionPath := dir + "/" + name + ".session"

	inner := "( " + command + " ) >" + q(logPath) + " 2>&1; __cx=$?; " +
		"printf '%s %s' \"$__cx\" \"$(date -u +%s)\" > " + q(exitPath+".tmp") + " 2>/dev/null && " +
		"mv -f " + q(exitPath+".tmp") + " " + q(exitPath) + "; exit $__cx"

	script := "set -e\n" +
		"d=" + q(dir) + "\n" +
		"mkdir -p \"$d\"\n" +
		": > " + q(logPath) + "\n" +
		"chmod 600 " + q(logPath) + " 2>/dev/null || true\n" +
		"rm -f " + q(exitPath) + " " + q(sessionPath) + "\n" +
		"cd " + q(home) + " 2>/dev/null || true\n" +
		"setsid sh -c " + q(inner) + " </dev/null >/dev/null 2>&1 &\n" +
		"pid=$!\n" +
		"disown 2>/dev/null || true\n" +
		"boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)\n" +
		"printf '%s %s\\n' \"$pid\" \"$boot\"\n"
	if sessionTrailer != "" {
		script += sessionTrailer + "\n"
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
	for _, ext := range []string{"json", "log", "exit", "session"} {
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

// StartBoxRun starts (or resumes) a coding-agent run on a box with no SSH
// client needed (#2193).
func (s *ContainerServer) StartBoxRun(ctx context.Context, req *pb.StartBoxRunRequest) (*pb.StartBoxRunResponse, error) {
	if err := validateBoxRunOwner(req.GetUsername()); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.GetPrompt()) == "" {
		return nil, status.Error(codes.InvalidArgument, "prompt is required")
	}
	if req.GetSessionId() != "" && req.GetContinueSession() {
		return nil, status.Error(codes.InvalidArgument, "session_id and continue_session are mutually exclusive")
	}
	if req.GetSessionId() != "" && !validRunPathID(req.GetSessionId()) {
		return nil, status.Errorf(codes.InvalidArgument, "session_id must match %s and not be . or ..", runIDPattern.String())
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}

	listExec := s.boxRunExecFn()
	startExec := s.boxRunStartExecFn()
	if listExec == nil || startExec == nil {
		return nil, status.Error(codes.Unavailable, "no container backend to start a run on")
	}

	name := req.GetSessionId()
	if name == "" {
		// #2193 accepted default: session_id doubles as run_name when
		// resuming via --session; a fresh run (or one resuming "whatever's
		// most recent" via continue_session) keeps the shared default name
		// `code run` itself uses.
		name = coderun.DefaultRunName
	}

	box := req.GetUsername() + "-container"
	dir := s.boxRunDir()

	collision, rotate, err := checkBoxRunCollision(listExec, box, dir, name)
	if err != nil {
		return nil, err
	}
	if collision != nil && !rotate {
		return nil, status.Errorf(codes.FailedPrecondition,
			"run %q on %q is already %s — no queueing; pick a different session, or wait for it to finish",
			name, req.GetUsername(), strings.ToLower(strings.TrimPrefix(collision.GetOutcome().String(), "BOX_RUN_OUTCOME_")))
	}
	if rotate {
		if _, err := startExec(box, req.GetUsername(), boxRunRotateScript(dir, name, collision.GetStartedAt().AsTime().Unix())); err != nil {
			return nil, status.Errorf(codes.Unavailable, "rotate finished run %q on %q: %v", name, req.GetUsername(), err)
		}
	}

	home, cfg, err := resolveBoxRunConfig(startExec, box, req.GetUsername())
	if err != nil {
		return nil, err
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

	command := eng.RunCommand(req.GetPrompt(), false, req.GetContinueSession(), req.GetSessionId())

	var sessionTrailer string
	if req.GetSessionId() != "" {
		// Already known from the request — write it immediately rather than
		// rediscovering it.
		sessionTrailer = sessionSidecarWriteCommand(dir, name, req.GetSessionId())
	} else if cmd, ok := engine.SessionDiscoveryBackgroundCommand(eng.Name(), home, home, dir+"/"+name+".session"); ok {
		sessionTrailer = cmd
	}

	out, err := startExec(box, req.GetUsername(), boxRunSpawnScript(dir, name, command, home, sessionTrailer))
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
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal run record: %v", err)
	}
	if _, err := startExec(box, req.GetUsername(), boxRunWriteRecordScript(dir, name, recordJSON)); err != nil {
		return nil, status.Errorf(codes.Unavailable, "persist run record for %q on %q: %v", name, req.GetUsername(), err)
	}

	run := boxRunProto(name, dir, record, agentbox.RunOutcomeRunning)
	if req.GetSessionId() != "" {
		run.SessionId = req.GetSessionId()
	}
	return &pb.StartBoxRunResponse{Run: run}, nil
}
