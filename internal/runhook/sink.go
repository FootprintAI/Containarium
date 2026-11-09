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

// Serve appends every valid event received on ln to cfg.EventsPath until ctx
// is done. It is the only writer of that file: run as root it creates the file
// 0600 in a 0700 directory, so the run user can neither write nor read it. It
// stamps time, run identity and approval from its own configuration, and
// redacts the arguments again, so a client can add events but cannot forge
// whose they are or when, or store a secret the redaction list covers.
func Serve(ctx context.Context, ln net.Listener, cfg Config, now func() time.Time) error {
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
	f, err := os.OpenFile(cfg.EventsPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := f.Chmod(0o600); err != nil {
		return err
	}

	var mu sync.Mutex
	appendEvent := func(e *pb.AgentCommandEvent) error {
		e.Time = timestamppb.New(now())
		e.RunName, e.RunId = cfg.RunName, cfg.RunID
		e.Approval = nil
		if cfg.Approval != nil {
			e.Approval = &pb.AgentRunApproval{ApprovalId: cfg.Approval.ID, ApproverId: cfg.Approval.Approver}
		}
		e.Argv = red.Argv(e.Argv)
		b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(e)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		if _, err := f.Write(append(b, '\n')); err != nil {
			return err
		}
		return f.Sync()
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
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
