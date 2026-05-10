package agentbox

import (
	"context"
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

const (
	processLogDir       = "/tmp/agent-box"
	processKillWaitTime = 2 * time.Second
)

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

	processRegistryMu.Lock()
	defer processRegistryMu.Unlock()

	if name == "" {
		name = fmt.Sprintf("proc-%d", time.Now().UnixNano())
	}
	if _, exists := processRegistry[name]; exists {
		return mcp.NewToolResultError(fmt.Sprintf(
			"process_start: a process named %q is already running; kill it first or pick a different name", name)),
			nil
	}

	if err := os.MkdirAll(processLogDir, 0o750); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("process_start: mkdir %s: %v", processLogDir, err)), nil
	}
	logPath := filepath.Join(processLogDir, sanitizeName(name)+".log")
	// #nosec G304 -- sanitizeName strips every char outside [A-Za-z0-9_.-],
	// so logPath is always /tmp/agent-box/<safe>.log. Path traversal is
	// not reachable from this construction.
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("process_start: open log %s: %v", logPath, err)), nil
	}

	// #nosec G204 -- process_start's contract is to spawn agent-supplied
	// commands; arbitrary command execution is the entire feature.
	cmd := exec.Command("/bin/sh", "-c", command)
	if cwd != "" {
		cmd.Dir = cwd
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// Detach from agent-box's process group so a child of the spawned
	// process survives an agent-box restart and can be reaped later.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return mcp.NewToolResultError(fmt.Sprintf("process_start: spawn: %v", err)), nil
	}

	mp := &managedProcess{
		Name:      name,
		PID:       cmd.Process.Pid,
		Command:   command,
		StartedAt: time.Now(),
		LogPath:   logPath,
		cmd:       cmd,
	}
	processRegistry[name] = mp

	// Reap exit asynchronously so we don't accumulate zombies. We don't
	// remove the entry from the registry on exit — a list call can still
	// surface it as not-alive, and the log file remains readable.
	go func() {
		_ = cmd.Wait()
		_ = logFile.Close()
	}()

	body := fmt.Sprintf(
		"name: %s\npid: %d\ncommand: %s\nlog_path: %s\nstarted_at: %s\n",
		mp.Name, mp.PID, mp.Command, mp.LogPath, mp.StartedAt.UTC().Format(time.RFC3339),
	)
	return mcp.NewToolResultText(body), nil
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
	processRegistryMu.Lock()
	procs := make([]*managedProcess, 0, len(processRegistry))
	for _, mp := range processRegistry {
		procs = append(procs, mp)
	}
	processRegistryMu.Unlock()

	if len(procs) == 0 {
		return mcp.NewToolResultText("No background processes registered.\n"), nil
	}

	sort.Slice(procs, func(i, j int) bool { return procs[i].StartedAt.Before(procs[j].StartedAt) })

	var b strings.Builder
	fmt.Fprintf(&b, "Found %d process(es):\n\n", len(procs))
	for _, mp := range procs {
		alive := isAlive(mp.PID)
		state := "alive"
		if !alive {
			state = "exited"
		}
		fmt.Fprintf(&b, "🟢 %s  (pid %d, %s)\n", mp.Name, mp.PID, state)
		fmt.Fprintf(&b, "   Command:    %s\n", mp.Command)
		fmt.Fprintf(&b, "   Started at: %s\n", mp.StartedAt.UTC().Format(time.RFC3339))
		fmt.Fprintf(&b, "   Log path:   %s\n", mp.LogPath)
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
	mp, ok := processRegistry[name]
	if !ok {
		processRegistryMu.Unlock()
		return mcp.NewToolResultError(fmt.Sprintf("process_kill: no process named %q", name)), nil
	}
	delete(processRegistry, name)
	processRegistryMu.Unlock()

	sig := syscall.SIGTERM
	signalName := "SIGTERM"
	if force {
		sig = syscall.SIGKILL
		signalName = "SIGKILL"
	}
	// Signal the entire process group so children also receive it.
	// Setsid above made each process its own session/group leader, so
	// PGID == PID and -PID targets the group.
	if err := syscall.Kill(-mp.PID, sig); err != nil {
		// If the process is already dead this returns ESRCH; that's
		// not a failure — the agent's intent ("kill it") is satisfied.
		if err != syscall.ESRCH {
			return mcp.NewToolResultError(fmt.Sprintf("process_kill: signal %s: %v", signalName, err)), nil
		}
	}

	// Best-effort wait for the process to actually exit so the agent's
	// next process_list reflects reality.
	deadline := time.Now().Add(processKillWaitTime)
	for time.Now().Before(deadline) {
		if !isAlive(mp.PID) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	body := fmt.Sprintf(
		"name: %s\npid: %d\nsignal: %s\nexited: %v\nlog_path: %s\n",
		mp.Name, mp.PID, signalName, !isAlive(mp.PID), mp.LogPath,
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
