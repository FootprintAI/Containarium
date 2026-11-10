package runhook

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The sink protocol: the hook sends one protojson AgentCommandEvent per line;
// the sink answers "ok" once the line is appended, or "error: <why>".

// maxEventLine bounds one event line.
const maxEventLine = 256 << 10

// sinkIOTimeout bounds one exchange on either side.
const sinkIOTimeout = 10 * time.Second

// syncFile flushes the events file to disk; a variable so a test can make it
// fail.
var syncFile = (*os.File).Sync

// RunExit is how the sink saw its run end.
type RunExit int32

const (
	// RunExitInterrupted is every end not proven clean: killed, timed out,
	// crashed, a non-zero or unreadable exit status, no exit status at all,
	// or the sink itself stopped by a signal.
	RunExitInterrupted RunExit = iota
	// RunExitClean is a run whose exit status is 0.
	RunExitClean
)

// openStart is a START the sink has stored and no END has closed yet.
type openStart struct {
	toolUseID string
	argv      []string
	class     pb.AgentCommandClass
}

// closingEnd is the END the sink writes for a START still open when the run
// ends. After a clean exit the engine finished without reporting the command
// (it fires a post hook for every command it runs), so the engine refused it
// and it did not run. After any other exit it may have run in part.
func closingEnd(o openStart, how RunExit) *pb.AgentCommandEvent {
	e := &pb.AgentCommandEvent{
		Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END, ToolUseId: o.toolUseID,
		Argv: o.argv, Class: o.class,
		CloseReason: pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_INTERRUPTED,
		Outcome:     pb.AgentCommandOutcome_AGENT_COMMAND_OUTCOME_UNKNOWN,
	}
	if how == RunExitClean {
		e.CloseReason = pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_ENGINE_REFUSED
		e.Outcome = pb.AgentCommandOutcome_AGENT_COMMAND_OUTCOME_NOT_RUN
	}
	return e
}

// Serve appends every valid event received on ln to cfg.EventsPath until ctx
// is done. It is the only writer of that file: run as root it creates the file
// 0600 in a 0700 directory, so the run user can neither write nor read it. It
// stamps time, run identity and approval from its own configuration, and
// redacts the arguments again, so a client can add events but cannot forge
// whose they are or when, or store a secret the redaction list covers.
//
// Every START gets exactly one END. A START still open when ctx is done (the
// run has ended) is closed by the sink itself, after every connection has
// finished, with closingEnd for exit(): this covers a command the engine
// refused after the pre hook (no post hook fires for it) and a run killed or
// crashed mid-command. A nil exit counts as RunExitInterrupted.
func Serve(ctx context.Context, ln net.Listener, cfg Config, now func() time.Time, exit func() RunExit) error {
	red, err := NewRedactor(cfg.RedactPatterns)
	if err != nil {
		return err
	}
	dir := filepath.Dir(cfg.EventsPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	// A restarted sink continues the run's sequence; a new start's marker
	// from an earlier sink is stale.
	if err := os.Remove(DonePath(cfg.EventsPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	last, err := lastSeq(cfg.EventsPath)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(cfg.EventsPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := f.Chmod(0o600); err != nil {
		return err
	}

	var mu sync.Mutex
	var open []openStart // in START order; guarded by mu
	seq := last          // the last seq written; guarded by mu
	appendEvent := func(e *pb.AgentCommandEvent) error {
		e.Time = timestamppb.New(now())
		e.RunName, e.RunId = cfg.RunName, cfg.RunID
		e.Approval = nil
		if cfg.Approval != nil {
			e.Approval = &pb.AgentRunApproval{ApprovalId: cfg.Approval.ID, ApproverId: cfg.Approval.Approver}
		}
		e.Argv = red.Argv(e.Argv)
		mu.Lock()
		defer mu.Unlock()
		// The sequence is the sink's alone: a client value is overwritten, and
		// a failed write does not consume a number.
		e.Seq = seq + 1
		b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			return err
		}
		// The line is in the file now, so its number is spent and the open
		// STARTs follow it whether or not the sync below succeeds. A failed
		// sync is still reported to the hook, but the next event must not
		// reuse this seq, and a START that was written still needs its END.
		seq = e.Seq
		switch e.GetKind() {
		case pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_START:
			open = append(open, openStart{toolUseID: e.GetToolUseId(), argv: e.GetArgv(), class: e.GetClass()})
		case pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END:
			for i, o := range open {
				if o.toolUseID == e.GetToolUseId() {
					open = append(open[:i], open[i+1:]...)
					break
				}
			}
		}
		return syncFile(f)
	}
	closeOpen := func() error {
		how := RunExitInterrupted
		if exit != nil {
			how = exit()
		}
		mu.Lock()
		pending := append([]openStart(nil), open...)
		mu.Unlock()
		var errs []error
		for _, o := range pending {
			errs = append(errs, appendEvent(closingEnd(o, how)))
		}
		return errors.Join(errs...)
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				wg.Wait()
				return errors.Join(closeOpen(), markDone(cfg.EventsPath))
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { _ = conn.Close() }()
			serveConn(conn, appendEvent)
		}()
	}
}

func serveConn(conn net.Conn, appendEvent func(*pb.AgentCommandEvent) error) {
	_ = conn.SetDeadline(time.Now().Add(sinkIOTimeout))
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), maxEventLine)
	for sc.Scan() {
		var e pb.AgentCommandEvent
		reply := "ok\n"
		if err := protojson.Unmarshal(sc.Bytes(), &e); err != nil {
			reply = "error: not an event\n"
		} else if e.GetKind() == pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_UNSPECIFIED {
			reply = "error: event kind is unspecified\n"
		} else if err := appendEvent(&e); err != nil {
			reply = "error: " + strings.ReplaceAll(err.Error(), "\n", " ") + "\n"
		}
		if _, err := conn.Write([]byte(reply)); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(sinkIOTimeout))
	}
}

// DialSender returns a Sender that delivers each event to the sink listening
// on socket and waits for it to be stored.
func DialSender(socket string) Sender {
	return func(e *pb.AgentCommandEvent) error {
		b, err := protojson.Marshal(e)
		if err != nil {
			return err
		}
		conn, err := net.DialTimeout("unix", socket, sinkIOTimeout)
		if err != nil {
			return fmt.Errorf("audit sink: %w", err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(sinkIOTimeout))
		if _, err := conn.Write(append(b, '\n')); err != nil {
			return fmt.Errorf("audit sink: %w", err)
		}
		reply, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return fmt.Errorf("audit sink: %w", err)
		}
		if reply != "ok\n" {
			return fmt.Errorf("audit sink: %s", strings.TrimSpace(reply))
		}
		return nil
	}
}

// lastSeq is the seq of the last event in an existing events file (0 for none).
// The file is the sink's alone, so it holds one event per line with seq equal to
// the line number; a file that does not end in a complete line, or whose last
// event has another seq, is refused rather than continued.
func lastSeq(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}
	if b[len(b)-1] != '\n' {
		return 0, fmt.Errorf("audit file %s does not end in a complete event", path)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	var e pb.AgentCommandEvent
	if err := protojson.Unmarshal([]byte(lines[len(lines)-1]), &e); err != nil {
		return 0, fmt.Errorf("audit file %s: last event: %w", path, err)
	}
	if e.GetSeq() != uint64(len(lines)) {
		return 0, fmt.Errorf("audit file %s: last event has seq %d on line %d", path, e.GetSeq(), len(lines))
	}
	return e.GetSeq(), nil
}

// markDone creates the done marker, 0600, once the last event is written.
func markDone(eventsPath string) error {
	f, err := os.OpenFile(DonePath(eventsPath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	return errors.Join(f.Chmod(0o600), f.Sync(), f.Close())
}
