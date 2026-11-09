//go:build !windows

package runhook

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// LoadConfig reads a run's configuration file.
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// RunHookCLI is `agent-box permission-hook pre|post --config <path>`. The pre
// hook always exits 0: its decision, including a fail-closed deny, is on
// stdout.
func RunHookCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 1 || (args[0] != "pre" && args[0] != "post") {
		fmt.Fprintln(stderr, "usage: agent-box permission-hook pre|post --config <path>")
		return 2
	}
	fs := flag.NewFlagSet("permission-hook", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "the run's hook configuration")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cfg, err := LoadConfig(*path)
	if args[0] == "pre" {
		if err != nil {
			_ = writeDeny(stdout, pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_AUDIT_UNAVAILABLE, "the hook configuration cannot be read")
			fmt.Fprintln(stderr, err)
			return 0
		}
		if err := RunPre(cfg, stdin, stdout, DialSender(cfg.Socket)); err != nil {
			fmt.Fprintln(stderr, err)
		}
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := RunPost(cfg, stdin, DialSender(cfg.Socket)); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// recordGrace is how long the sink waits for its run's record to appear.
const recordGrace = 10 * time.Minute

// runRecordHead is the part of agent-box's run record the sink reads.
type runRecordHead struct {
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
}

// runEnded reports whether the run named name, started no earlier than since,
// has ended: its exit sidecar is newer than since, or its record's process is
// gone, or no record of it appeared within recordGrace. The run user can write
// these files; the worst it can do is stop the sink early, after which every
// command is refused (the hook fails closed), or keep it alive longer.
func runEnded(runDir, name string, since, now time.Time, alive func(pid int) bool) bool {
	if fi, err := os.Stat(filepath.Join(runDir, name+".exit")); err == nil && !fi.ModTime().Before(since) {
		return true
	}
	var rec runRecordHead
	if b, err := os.ReadFile(filepath.Join(runDir, name+".json")); err == nil && json.Unmarshal(b, &rec) == nil &&
		rec.PID > 0 && !rec.StartedAt.Before(since.Add(-time.Minute)) {
		return !alive(rec.PID)
	}
	return now.Sub(since) > recordGrace
}

func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// RunSinkCLI is `agent-box run-audit-sink --config <path> --run-dir <dir>`,
// started detached, as root, by the daemon before the run. It serves the
// run's socket until the run ends.
func RunSinkCLI(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("run-audit-sink", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "the run's configuration")
	runDir := fs.String("run-dir", "", "the directory of the run's record and exit sidecar")
	if err := fs.Parse(args); err != nil || *path == "" || *runDir == "" {
		fmt.Fprintln(stderr, "usage: agent-box run-audit-sink --config <path> --run-dir <dir>")
		return 2
	}
	cfg, err := LoadConfig(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Socket), 0o755); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := os.Remove(cfg.Socket); err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ln, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	// Any local user may connect (the hooks run as the run user); only this
	// process writes the events file.
	if err := os.Chmod(cfg.Socket, 0o666); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer func() { _ = os.Remove(cfg.Socket) }()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	since := time.Now()
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				if runEnded(*runDir, cfg.RunName, since, now, pidAlive) {
					cancel()
					return
				}
			}
		}
	}()
	if err := Serve(ctx, ln, cfg, time.Now); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
