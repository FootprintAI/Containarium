package runhook

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The sink is the only writer of the audit file: it stamps run identity,
// approval and time from its own configuration, redacts the arguments, and
// appends one protojson line per event.
func TestSink_StampsRedactsAndAppends(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "r1.sock")
	out := filepath.Join(dir, "events", "r1.jsonl")
	cfg := testConfig()
	cfg.Socket = sock
	cfg.EventsPath = out
	cfg.Approval = &Approval{ID: "appr-1", Approver: "user-7"}

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixed := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, cfg, func() time.Time { return fixed }) }()

	send := DialSender(sock)
	forged := &pb.AgentCommandEvent{
		Kind:      pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_START,
		RunName:   "someone-else",
		RunId:     "forged",
		Time:      timestamppb.New(time.Unix(0, 0)),
		Approval:  &pb.AgentRunApproval{ApprovalId: "forged", ApproverId: "forged"},
		ToolUseId: "toolu_1",
		Argv:      []string{"deploy", "--token=ghp_0123456789abcdefghij0123456789abcdef"},
		Class:     pb.AgentCommandClass_AGENT_COMMAND_CLASS_ALLOWLISTED,
	}
	if err := send(forged); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := send(&pb.AgentCommandEvent{Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END, ToolUseId: "toolu_1"}); err != nil {
		t.Fatalf("send: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2:\n%s", len(lines), data)
	}
	var e pb.AgentCommandEvent
	if err := protojson.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatal(err)
	}
	if e.GetRunName() != "r1" || e.GetRunId() != "id1" || !e.GetTime().AsTime().Equal(fixed) {
		t.Errorf("identity/time not stamped by the sink: %v", &e)
	}
	if e.GetApproval().GetApprovalId() != "appr-1" || e.GetApproval().GetApproverId() != "user-7" {
		t.Errorf("approval not stamped from the sink's configuration: %v", e.GetApproval())
	}
	if strings.Contains(lines[0], "ghp_0123456789") {
		t.Errorf("token reached the audit file: %s", lines[0])
	}

	// The file and its directory are private to the sink's user.
	if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("events file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	if fi, err := os.Stat(filepath.Dir(out)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("events dir mode = %v (%v), want 0700", fi.Mode().Perm(), err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sink did not stop")
	}
}

func TestSink_RejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	cfg := testConfig()
	cfg.EventsPath = filepath.Join(dir, "ev", "r1.jsonl")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, ln, cfg, time.Now) }()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("not json\n"))
	buf := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := c.Read(buf)
	if strings.HasPrefix(string(buf[:n]), "ok") {
		t.Fatalf("garbage was acknowledged: %q", buf[:n])
	}
	if data, _ := os.ReadFile(cfg.EventsPath); len(data) != 0 {
		t.Errorf("garbage reached the audit file: %q", data)
	}
}
