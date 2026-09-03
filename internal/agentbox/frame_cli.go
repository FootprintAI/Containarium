package agentbox

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/footprintai/containarium/internal/logframe"
)

// `agent-box frame <stream> <log>` — the child-side half of framed capture
// (#1701).
//
// Framing used to happen inside agent-box: cmd.Stdout was a frameWriter, an
// io.Writer rather than an *os.File, so os/exec put a pipe between the child
// and a copier goroutine in agent-box's address space. agent-box is a stdio
// MCP server spawned per SSH connection, so when the connection dropped its
// exit closed the read end and the child died of SIGPIPE on its next write —
// destroying exactly the detached run that #1672/#1674 exist to keep alive.
// Combined mode never had the bug: cmd.Stdout was the *os.File itself, whose
// descriptor the child inherits.
//
// So framing moves to the child's side of the fork. spawnBackgroundProcess
// starts one of these per stream, inside the same setsid'd shell as the
// command, reading a FIFO the command writes to. Nothing in the path depends
// on agent-box still being alive.
//
// Both framers append to ONE log, so the single-offset contract tail_log
// serves is unchanged. They serialize with an flock on the log file: frames
// can exceed PIPE_BUF, so O_APPEND alone would not keep two writers from
// interleaving mid-frame.
func RunFrameCLI(args []string, stdin io.Reader, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: agent-box frame <1|2> <log-path>")
		return 2
	}
	// logframe.Stream is the ASCII BYTE the wire format uses ('1'/'2'), not
	// the integer 1/2 — so match the argument against the constants directly
	// rather than parsing it as a number and comparing domains.
	var stream logframe.Stream
	switch args[0] {
	case string(rune(logframe.Stdout)):
		stream = logframe.Stdout
	case string(rune(logframe.Stderr)):
		stream = logframe.Stderr
	default:
		fmt.Fprintf(stderr, "frame: stream must be %q (stdout) or %q (stderr), got %q\n",
			rune(logframe.Stdout), rune(logframe.Stderr), args[0])
		return 2
	}

	// #nosec G304 -- the log path is agent-box's own, built from sanitizeName
	// in spawnBackgroundProcess; this process is spawned by that same code.
	log, err := os.OpenFile(args[1], os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "frame: open %s: %v\n", args[1], err)
		return 1
	}
	defer func() { _ = log.Close() }()

	buf := make([]byte, 32*1024)
	for {
		n, readErr := stdin.Read(buf)
		if n > 0 {
			if werr := appendFrameLocked(log, stream, buf[:n]); werr != nil {
				fmt.Fprintf(stderr, "frame: write: %v\n", werr)
				return 1
			}
		}
		if readErr == io.EOF {
			return 0
		}
		if readErr != nil {
			// The writer going away is the normal end of a run, not a fault.
			return 0
		}
	}
}

// appendFrameLocked writes one frame under an exclusive advisory lock, so the
// stdout and stderr framers never interleave mid-record in the shared log.
// This is the cross-process equivalent of the mutex the in-process
// frameWriter used to share.
func appendFrameLocked(log *os.File, stream logframe.Stream, payload []byte) error {
	if err := syscall.Flock(int(log.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	defer func() { _ = syscall.Flock(int(log.Fd()), syscall.LOCK_UN) }()

	if _, err := log.Write(logframe.EncodeFrame(stream, payload)); err != nil {
		return err
	}
	return nil
}
