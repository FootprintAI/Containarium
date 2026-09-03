package agentbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ErrProcessNameInUse is returned by spawnBackgroundProcess when name
// already names a registered process. Sentinel (rather than a plain
// fmt.Errorf) because SpawnService.Spawn (gRPC, #1488 Phase 2) needs to
// map it to codes.AlreadyExists specifically — a client-correctable
// conflict, not a server malfunction — without string-matching the
// message. The MCP handler doesn't need to distinguish it (it only
// surfaces the message text), so it keeps using %v/%w against this error
// like any other.
var ErrProcessNameInUse = errors.New("process name already in use")

// Process management.
//
// shell_exec is bounded — runs a single command for up to 10 minutes and
// returns its output. process_start fills the gap when an agent needs
// something long-lived: a dev server, a build, a watcher. The agent
// kicks it off with process_start, watches it via tail_log on the
// returned log_path, and reaps it with process_kill.
//
// State lives in-memory (a package-level registry). Processes survive
// tool calls but NOT agent-box restarts. Output is captured to
// /tmp/agent-box/<name>.log so even after the process exits the agent
// can still read what it produced (until /tmp gets cleared).

// processLogDir is a var, not a const, so tests can point it at t.TempDir()
// (#1672 design doc, finding A1) — run-record tests assert on-disk state
// and must stay isolated from the real /tmp/agent-box to be parallel-safe.
var processLogDir = defaultProcessLogDir()

// defaultProcessLogDir resolves where run logs, records, and exit sidecars
// live. AGENTBOX_LOG_DIR overrides it — needed by tests that run a REAL
// agent-box subprocess (the only way to reproduce the parent-exit case behind
// #1701, since an in-process spawn keeps the parent alive), and useful to an
// operator who does not want run state on /tmp.
// agentBoxSelfPath resolves the agent-box binary the framer children exec
// (#1701). os.Executable() is right in production — agent-box spawns the run —
// but it is whatever binary embeds this package, which is not agent-box under
// `go test`, nor in any host process that imports agentbox as a library.
// AGENTBOX_SELF names it explicitly for those cases.
func agentBoxSelfPath() (string, error) {
	if p := os.Getenv("AGENTBOX_SELF"); p != "" {
		return p, nil
	}
	return os.Executable()
}

func defaultProcessLogDir() string {
	if dir := os.Getenv("AGENTBOX_LOG_DIR"); dir != "" {
		return dir
	}
	return "/tmp/agent-box"
}

const processKillWaitTime = 2 * time.Second

type managedProcess struct {
	Name      string
	PID       int
	Command   string
	StartedAt time.Time
	LogPath   string

	cmd *exec.Cmd
}

var (
	processRegistry   = make(map[string]*managedProcess)
	processRegistryMu sync.Mutex
)

// reapWG tracks in-flight reap goroutines (cmd.Wait() + the final
// writeRunRecordAt). Production has no reason to wait on it — the whole
// point of async reaping is not blocking the caller — but tests that kill a
// process and then tear down its (TempDir-backed) processLogDir need to
// know the reaper's write has actually landed first; see
// waitForReapersForTest.
var reapWG sync.WaitGroup

func registerProcessTools(s *server.MCPServer) {
	s.AddTool(processStartTool(), handleProcessStart)
	s.AddTool(processListTool(), handleProcessList)
	s.AddTool(processKillTool(), handleProcessKill)
}

// ----- process_start ---------------------------------------------------

func processStartTool() mcp.Tool {
	return mcp.NewTool(
		"process_start",
		mcp.WithDescription(
			"Spawn a long-running shell command in the background. Returns the "+
				"process name (caller-supplied or auto-generated), PID, and a log "+
				"path under /tmp/agent-box where stdout+stderr are captured. The "+
				"agent watches output via tail_log on the log_path and reaps the "+
				"process via process_kill. Use this when the work outlives a single "+
				"shell_exec call — dev servers, watchers, builds.",
		),
		mcp.WithString("command",
			mcp.Description("Shell command to spawn, e.g. 'npm run dev' or 'caddy run'."),
			mcp.Required(),
		),
		mcp.WithString("name",
			mcp.Description("Stable identifier for later list/kill calls. Auto-generated if omitted. Must be unique across active processes."),
		),
		mcp.WithString("cwd",
			mcp.Description("Working directory for the spawned process. Default: agent-box's cwd."),
		),
		mcp.WithString("actor",
			mcp.Description("Optional provenance: the principal that authorized this run, recorded on the run record so a later reconnect can say who started it. CALLER-ASSERTED — agent-box cannot verify it (no authenticated context on this transport), so it is weaker evidence than a platform audit row. Omit rather than guess: empty records the run as unattributed, which is better than attributing it wrongly."),
		),
		mcp.WithString("delegation_chain",
			mcp.Description("Optional JSON-serialized delegation chain behind `actor` (the act claim shape). Same caller-asserted caveat."),
		),
		mcp.WithString("capture_mode",
			mcp.Description("How to capture stdout+stderr: 'combined' (default) writes plain text, "+
				"readable with a plain tail/cat. 'framed' interleaves stdout and stderr as "+
				"line-framed, base64-encoded records a client can demultiplex — opt in only if "+
				"you're driving this process through a demuxing client (#1674); a human tailing "+
				"the log wants 'combined'."),
			mcp.Enum("combined", "framed"),
		),
	)
}

func handleProcessStart(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	command, _ := args["command"].(string)
	if command == "" {
		return mcp.NewToolResultError("process_start: 'command' is required"), nil
	}
	name, _ := args["name"].(string)
	cwd, _ := args["cwd"].(string)
	captureModeArg, _ := args["capture_mode"].(string)
	captureMode, err := parseCaptureMode(captureModeArg)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("process_start: %v", err)), nil
	}

	actor, _ := args["actor"].(string)
	delegationChain, _ := args["delegation_chain"].(string)

	mp, err := spawnBackgroundProcess(name, command, cwd, captureMode, actor, delegationChain)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("process_start: %v", err)), nil
	}

	body := fmt.Sprintf(
		"name: %s\npid: %d\ncommand: %s\nlog_path: %s\nstarted_at: %s\n",
		mp.Name, mp.PID, mp.Command, mp.LogPath, mp.StartedAt.UTC().Format(time.RFC3339),
	)
	return mcp.NewToolResultText(body), nil
}

// spawnBackgroundProcess starts command under /bin/sh -c, detached via
// Setsid, capturing stdout+stderr to a log file under processLogDir per
// captureMode (#1674), and registers it in processRegistry under name
// (auto-generated if empty). Reaped asynchronously — a goroutine calls
// cmd.Wait() — so it never zombies.
//
// Shared core between the process_start MCP tool (handleProcessStart) and
// SpawnService.Spawn (gRPC, #1488 Phase 2): one implementation, two
// transports, so a caller reaching agent-box over the fast local socket
// gets identical spawn/reap semantics to one reaching it over MCP/SSH.
func spawnBackgroundProcess(name, command, cwd string, captureMode CaptureMode, actor, delegationChain string) (*managedProcess, error) {
	if command == "" {
		return nil, fmt.Errorf("'command' is required")
	}

	processRegistryMu.Lock()
	defer processRegistryMu.Unlock()

	if name == "" {
		name = fmt.Sprintf("proc-%d", time.Now().UnixNano())
	}
	if _, exists := processRegistry[name]; exists {
		return nil, fmt.Errorf("%w: a process named %q is already running; kill it first or pick a different name", ErrProcessNameInUse, name)
	}

	// Collision check against durable records, not just the in-memory
	// registry: after a reconnect the registry is empty, so without this a
	// reused name would pass the check above and O_TRUNC the previous run's
	// log below — destroying exactly the output #1672 exists to preserve.
	if existing, found, err := readRunRecord(name); err != nil {
		return nil, fmt.Errorf("check existing run record for %q: %w", name, err)
	} else if found {
		switch ResolveOutcome(existing, bootID, isAlive) {
		case RunOutcomeRunning, RunOutcomeUnknown:
			// unknown is refused too: it is the only evidence of an
			// unresolved run (A2), and destroying it here would make that
			// run's outcome unrecoverable forever.
			return nil, fmt.Errorf("%w: a process named %q is already running; kill it first or pick a different name", ErrProcessNameInUse, name)
		case RunOutcomeExited:
			if err := rotateFinishedRun(existing); err != nil {
				return nil, fmt.Errorf("rotate finished run %q: %w", name, err)
			}
		}
	}

	// Captured once, here, and used for the rest of this run's lifecycle
	// (including the async reap goroutine below) instead of re-reading the
	// processLogDir package var later: that var may legitimately be a
	// different value by the time the reaper runs (tests repoint it per
	// test; nothing stops a future caller from doing the same), and an
	// unsynchronized cross-goroutine read of it would be a data race
	// regardless.
	logDir := processLogDir
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", logDir, err)
	}
	logPath := filepath.Join(logDir, sanitizeName(name)+".log")
	// #nosec G304 -- sanitizeName strips every char outside [A-Za-z0-9_.-],
	// so logPath is always logDir/<safe>.log (logDir is /tmp/agent-box in
	// production, a test's own TempDir in tests). Path traversal is not
	// reachable from this construction.
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open log %s: %w", logPath, err)
	}

	// #nosec G204 -- spawning agent-supplied commands is the entire
	// feature, on both transports this function serves.
	// Wrap so the CHILD records its own exit status (#1693). The reap
	// goroutine below only runs while this agent-box is alive, and
	// agent-box dies with its SSH connection — so for a detached run (the
	// whole point of #1672) nothing in-process survives to write the
	// outcome. The setsid'd child does, so it writes the sidecar itself.
	// Framed capture frames on the CHILD's side of the fork (#1701). Handing
	// exec.Cmd an io.Writer instead of an *os.File makes it insert a pipe and
	// a copier goroutine inside agent-box; when the SSH connection drops and
	// agent-box exits, the child dies of SIGPIPE on its next write. So both
	// modes now give the child a real descriptor: combined writes the log
	// directly, framed writes FIFOs that setsid'd framer children drain.
	var framing *framingSpec
	if captureMode == CaptureFramed {
		self, err := agentBoxSelfPath()
		if err != nil {
			_ = logFile.Close()
			return nil, fmt.Errorf("locate agent-box for framed capture: %w", err)
		}
		framing = &framingSpec{
			agentBox: self,
			logPath:  logPath,
			outFIFO:  filepath.Join(logDir, sanitizeName(name)+".out.fifo"),
			errFIFO:  filepath.Join(logDir, sanitizeName(name)+".err.fifo"),
		}
	}

	// #nosec G204 -- spawning agent-supplied commands is the entire feature.
	cmd := exec.Command("/bin/sh", "-c", buildRunScript(command, exitSidecarPath(logDir, name), framing))
	if cwd != "" {
		cmd.Dir = cwd
	}
	// Both modes hand the child a real *os.File. In framed mode the child's
	// own stdout/stderr are redirected to the FIFOs by the script, so these
	// only carry anything the script itself emits (e.g. an mkfifo failure).
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// Detach from agent-box's process group so a child of the spawned
	// process survives an agent-box restart and can be reaped later.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("spawn: %w", err)
	}

	startedAt := time.Now()
	record := RunRecord{
		Version:     RunRecordVersion,
		Name:        name,
		PID:         cmd.Process.Pid,
		BootID:      bootID,
		Command:     command,
		Cwd:         cwd,
		CaptureMode: captureMode,
		LogPath:     logPath,
		StartedAt:   startedAt,
		// Caller-asserted provenance (#1699) — see RunRecord.Actor for why
		// this is not, and cannot be on this transport, an authenticated
		// attribution.
		Actor:           actor,
		DelegationChain: delegationChain,
	}
	// Written before returning, so the run is discoverable even if the
	// caller (or agent-box itself) dies immediately after this call. A run
	// that can't be durably recorded is exactly the pre-#1672 bug, so this
	// fails the spawn rather than silently degrading back to it.
	if err := writeRunRecordAt(logDir, record); err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = logFile.Close()
		return nil, fmt.Errorf("write run record: %w", err)
	}

	mp := &managedProcess{
		Name:      name,
		PID:       cmd.Process.Pid,
		Command:   command,
		StartedAt: startedAt,
		LogPath:   logPath,
		cmd:       cmd,
	}
	processRegistry[name] = mp

	// Reap exit asynchronously so we don't accumulate zombies. We don't
	// remove the entry from the registry on exit — a list call can still
	// surface it as not-alive, and the log file remains readable.
	reapWG.Add(1)
	go func() {
		defer reapWG.Done()
		_ = cmd.Wait()
		_ = logFile.Close()

		// Record the outcome instead of discarding it (the second finding
		// #1672 fixes). ProcessState is set by Wait() whenever it actually
		// waited on the process — including a signaled exit, where
		// ExitCode() reports -1 rather than a WIFSIGNALED detail; either
		// way ExitCode becomes non-nil, so ResolveOutcome reports "exited"
		// rather than leaving the run's fate undetermined.
		finishedAt := time.Now()
		exitCode := cmd.ProcessState.ExitCode()
		finished := record
		finished.FinishedAt = &finishedAt
		finished.ExitCode = &exitCode
		// Best-effort: the process has already exited either way, and a
		// write failure here (disk full, box dying) leaves the run
		// correctly classified as "unknown" (A2) rather than silently
		// "exited" — never a false clean exit. writeRunRecordAt(logDir, ...)
		// — not writeRunRecord — deliberately: see the logDir comment above.
		_ = writeRunRecordAt(logDir, finished)
	}()

	return mp, nil
}

// ----- process_list ----------------------------------------------------

func processListTool() mcp.Tool {
	return mcp.NewTool(
		"process_list",
		mcp.WithDescription(
			"List background processes started via process_start. Reports PID, command, "+
				"start time, log_path, and a liveness flag. Processes that have already "+
				"exited still appear here until process_kill is called on them — useful "+
				"for inspecting their final log output via tail_log.",
		),
	)
}

func handleProcessList(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Sourced from durable records, not processRegistry: the registry is
	// per-agent-box-instance and empty after a reconnect, but a run started
	// by a PRIOR instance must still be reported here (#1672) — including
	// one that finished while no client was connected at all.
	records, err := listRunRecords()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("process_list: %v", err)), nil
	}

	if len(records) == 0 {
		return mcp.NewToolResultText("No background processes registered.\n"), nil
	}

	sort.Slice(records, func(i, j int) bool { return records[i].StartedAt.Before(records[j].StartedAt) })

	var b strings.Builder
	fmt.Fprintf(&b, "Found %d process(es):\n\n", len(records))
	for _, r := range records {
		outcome := ResolveOutcome(r, bootID, isAlive)
		icon := "🟢"
		if outcome != RunOutcomeRunning {
			icon = "⚪"
		}
		fmt.Fprintf(&b, "%s %s  (pid %d, %s)\n", icon, r.Name, r.PID, outcome)
		fmt.Fprintf(&b, "   Command:    %s\n", r.Command)
		fmt.Fprintf(&b, "   Started at: %s\n", r.StartedAt.UTC().Format(time.RFC3339))
		if r.Actor != "" {
			// "asserted" is load-bearing: this is what the client claimed, not
			// what the platform verified (#1699).
			fmt.Fprintf(&b, "   Actor:      %s (asserted)\n", r.Actor)
		}
		if r.ExitCode != nil {
			fmt.Fprintf(&b, "   Exit code:  %d\n", *r.ExitCode)
		}
		if r.FinishedAt != nil {
			fmt.Fprintf(&b, "   Finished at: %s\n", r.FinishedAt.UTC().Format(time.RFC3339))
		}
		fmt.Fprintf(&b, "   Log path:   %s\n", r.LogPath)
		b.WriteString("\n")
	}
	return mcp.NewToolResultText(b.String()), nil
}

// ----- process_kill ----------------------------------------------------

func processKillTool() mcp.Tool {
	return mcp.NewTool(
		"process_kill",
		mcp.WithDescription(
			"Stop a process started via process_start. Sends SIGTERM by default and "+
				"waits up to 2s for the process to exit. Pass force=true for SIGKILL. "+
				"Removes the process from the registry on success — the log file is "+
				"left in place so the agent can still read final output via tail_log.",
		),
		mcp.WithString("name",
			mcp.Description("Process name (as returned by process_start or process_list)."),
			mcp.Required(),
		),
		mcp.WithBoolean("force",
			mcp.Description("Send SIGKILL instead of SIGTERM. Default false."),
			mcp.DefaultBool(false),
		),
	)
}

func handleProcessKill(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	name, _ := args["name"].(string)
	if name == "" {
		return mcp.NewToolResultError("process_kill: 'name' is required"), nil
	}
	force, _ := args["force"].(bool)

	processRegistryMu.Lock()
	mp, inRegistry := processRegistry[name]
	if inRegistry {
		delete(processRegistry, name)
	}
	processRegistryMu.Unlock()

	var pid int
	var logPath string
	if inRegistry {
		pid = mp.PID
		logPath = mp.LogPath
	} else {
		// Not tracked by THIS agent-box instance — fall back to the durable
		// record so a run started before a reconnect can still be found and
		// stopped (#1672).
		record, found, err := readRunRecord(name)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("process_kill: %v", err)), nil
		}
		if !found {
			return mcp.NewToolResultError(fmt.Sprintf("process_kill: no process named %q", name)), nil
		}
		switch ResolveOutcome(record, bootID, isAlive) {
		case RunOutcomeUnknown:
			// Boot id mismatch (or the process died before the reaper could
			// record its exit), so this PID may have been reassigned by the
			// kernel — signaling it could kill an unrelated process. Refuse
			// rather than guess (design doc, Part A).
			return mcp.NewToolResultError(fmt.Sprintf(
				"process_kill: %q's outcome is unknown (predates this boot, or exited before it could be recorded) — refusing to signal pid %d, which may have been reassigned by the kernel",
				name, record.PID)), nil
		case RunOutcomeExited:
			return mcp.NewToolResultText(fmt.Sprintf(
				"name: %s\npid: %d\nsignal: none\nexited: true\nlog_path: %s\n",
				name, record.PID, record.LogPath)), nil
		}
		pid = record.PID
		logPath = record.LogPath
	}

	sig := syscall.SIGTERM
	signalName := "SIGTERM"
	if force {
		sig = syscall.SIGKILL
		signalName = "SIGKILL"
	}
	// Signal the entire process group so children also receive it.
	// Setsid above made each process its own session/group leader, so
	// PGID == PID and -PID targets the group.
	if err := syscall.Kill(-pid, sig); err != nil {
		// If the process is already dead this returns ESRCH; that's
		// not a failure — the agent's intent ("kill it") is satisfied.
		if err != syscall.ESRCH {
			return mcp.NewToolResultError(fmt.Sprintf("process_kill: signal %s: %v", signalName, err)), nil
		}
	}

	// Best-effort wait for the process to actually exit so the agent's
	// next process_list reflects reality. For a process this instance
	// spawned, the reap goroutine records the exit code concurrently; for
	// one recovered from a durable record only, we can't waitpid a
	// non-child, so its record keeps ExitCode absent and later resolves to
	// "unknown" — an honest report of "signaled, outcome not confirmed,"
	// never a false clean exit.
	deadline := time.Now().Add(processKillWaitTime)
	for time.Now().Before(deadline) {
		if !isAlive(pid) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	body := fmt.Sprintf(
		"name: %s\npid: %d\nsignal: %s\nexited: %v\nlog_path: %s\n",
		name, pid, signalName, !isAlive(pid), logPath,
	)
	return mcp.NewToolResultText(body), nil
}

// ----- helpers ---------------------------------------------------------

// isAlive returns true if a process with the given PID exists and the
// kernel hasn't reaped it yet. signal(0) is the canonical "is this PID
// alive?" check on Unix.
func isAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, syscall.Signal(0)) == nil
}

// sanitizeName strips characters that wouldn't be safe in a filename,
// since the name is used as part of the log path. Replaces anything
// non-alphanumeric/dash/underscore with underscore.
func sanitizeName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// resetProcessRegistryForTest removes all entries WITHOUT killing the
// underlying processes. Tests that spawn real processes are responsible
// for killing them before this is called; otherwise the test leaks.
func resetProcessRegistryForTest() {
	processRegistryMu.Lock()
	processRegistry = make(map[string]*managedProcess)
	processRegistryMu.Unlock()
}

// waitForReapersForTest blocks until every currently in-flight reap
// goroutine has finished its final writeRunRecordAt. A test that repoints
// processLogDir at its own t.TempDir() must call this (killAllAndReset
// does) before that directory gets torn down — otherwise a reaper can still
// be writing into it after Go's t.TempDir() cleanup has already removed it.
func waitForReapersForTest() {
	reapWG.Wait()
}
