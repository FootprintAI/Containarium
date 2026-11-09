//go:build !windows

package runhook

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// BlockedExitCode is a command-mode run's exit code when the command policy
// refuses its command (or cannot record its start): the command never ran. The
// typed reason is on the BLOCKED event and on stderr.
const BlockedExitCode = 120

// CommandToolUseID tags a command-mode run's events in place of an engine's
// tool-use id: the run has exactly one command.
const CommandToolUseID = "command"

// ShellRunner runs a command line through the shell and returns its exit code.
type ShellRunner func(command string) int32

// RunCommand is a command-mode run under a command policy (#3582): the same
// decision as the engine's PreToolUse hook applied to cfg.Command, then the
// command itself, then the same END as the PostToolUse hook. A refusal records
// a BLOCKED event with its typed reason, prints the reason, and ends the run
// with BlockedExitCode without running anything; so does a start that cannot be
// recorded.
func RunCommand(cfg Config, stderr io.Writer, send Sender, run ShellRunner) int {
	if cfg.Command == "" {
		fmt.Fprintln(stderr, refusal(pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_NOT_ALLOWED, "the configuration names no command"))
		return BlockedExitCode
	}
	d := Decide(cfg, cfg.Command)
	ev := &pb.AgentCommandEvent{ToolUseId: CommandToolUseID, Argv: d.Argv, Class: d.Class}
	if d.Verdict == VerdictDeny {
		ev.Kind = pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_BLOCKED
		ev.CloseReason = d.CloseReason
		if err := send(ev); err != nil {
			fmt.Fprintf(stderr, "the blocked event could not be recorded: %v\n", err)
		}
		fmt.Fprintln(stderr, refusal(d.CloseReason, d.Reason))
		return BlockedExitCode
	}
	// An allowlisted command and one the level covers both run: there is no
	// engine to defer to, and Decide has already applied the level's rules.
	ev.Kind = pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_START
	if err := send(ev); err != nil {
		fmt.Fprintln(stderr, refusal(pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_AUDIT_UNAVAILABLE,
			"the start event could not be recorded: "+err.Error()))
		return BlockedExitCode
	}
	code := run(cfg.Command)
	end := &pb.AgentCommandEvent{Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END,
		ToolUseId: CommandToolUseID, Argv: d.Argv, ExitCode: &code,
		Outcome: pb.AgentCommandOutcome_AGENT_COMMAND_OUTCOME_RAN}
	if err := send(end); err != nil {
		fmt.Fprintf(stderr, "the end event could not be recorded: %v\n", err)
	}
	return int(code)
}

func refusal(reason pb.AgentCommandCloseReason, why string) string {
	return fmt.Sprintf("command refused (%s): %s. The run ends; an approval starts a new run.", reason, why)
}

// RunShell runs command through `sh -c` with this process's stdio, forwarding
// SIGTERM, SIGINT and SIGHUP (the run's timeout and StopBoxRun) so the END is
// still recorded. A command killed by a signal reports 128+signal, as a shell
// does.
func RunShell(command string) int32 {
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 127
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				_ = cmd.Process.Signal(s)
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return exitStatus(128 + int(ws.Signal()))
		}
		return exitStatus(ee.ExitCode())
	}
	return 127
}

// exitStatus narrows a process exit status (0-255, or 128+signal) to the
// event's int32; anything out of that range is reported as 255.
func exitStatus(n int) int32 {
	if n < 0 || n > 255 {
		return 255
	}
	return int32(n)
}
