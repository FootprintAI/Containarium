package runhook

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	go func() { done <- Serve(ctx, ln, cfg, func() time.Time { return fixed }, nil) }()

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
	served := make(chan struct{})
	go func() { _ = Serve(ctx, ln, cfg, time.Now, nil); close(served) }()
	// The sink writes its done marker as it stops: let it finish before the
	// temp directory goes.
	defer func() { cancel(); <-served }()

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

// Every event the sink writes carries a sequence number the sink assigns:
// 1, 2, 3, ... contiguous across START, END and BLOCKED, whatever the client
// put in the field.
func TestSink_AssignsContiguousSeqAcrossKinds(t *testing.T) {
	_, send, stop := startSink(t, nil)
	evs := []*pb.AgentCommandEvent{
		{Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_START, ToolUseId: "t1", Seq: 99},
		{Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END, ToolUseId: "t1", Seq: 7},
		{Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_BLOCKED, ToolUseId: "t2", CloseReason: pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_NOT_ALLOWED},
		{Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_START, ToolUseId: "t3"},
	}
	for _, e := range evs {
		if err := send(e); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	got := stop() // t3's START is closed by the sink: one more event
	if len(got) != 5 {
		t.Fatalf("got %d events, want 5", len(got))
	}
	for i, e := range got {
		if e.GetSeq() != uint64(i+1) {
			t.Errorf("event %d seq = %d, want %d", i, e.GetSeq(), i+1)
		}
	}
	if got[4].GetKind() != pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END {
		t.Errorf("last event = %v, want the sink's closing END", got[4].GetKind())
	}
}

// Concurrent senders still get a gap-free, duplicate-free sequence in file
// order.
func TestSink_SeqIsGaplessUnderConcurrency(t *testing.T) {
	_, send, stop := startSink(t, nil)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = send(&pb.AgentCommandEvent{Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_BLOCKED, ToolUseId: "t"})
		}()
	}
	wg.Wait()
	for i, e := range stop() {
		if e.GetSeq() != uint64(i+1) {
			t.Fatalf("line %d has seq %d, want %d", i+1, e.GetSeq(), i+1)
		}
	}
}

// A sink started again for the same run continues after the last event in the
// file, so a seq is never reused.
func TestSink_SeqContinuesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	cfg.EventsPath = filepath.Join(dir, "events", "r1.jsonl")
	run := func(n int) {
		cfg.Socket = filepath.Join(dir, "r1.sock")
		_ = os.Remove(cfg.Socket)
		ln, err := net.Listen("unix", cfg.Socket)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Serve(ctx, ln, cfg, time.Now, nil) }()
		for i := 0; i < n; i++ {
			if err := DialSender(cfg.Socket)(&pb.AgentCommandEvent{Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_BLOCKED}); err != nil {
				t.Fatal(err)
			}
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	run(2)
	run(2)
	for i, e := range readEvents(t, cfg.EventsPath) {
		if e.GetSeq() != uint64(i+1) {
			t.Errorf("line %d seq = %d, want %d", i+1, e.GetSeq(), i+1)
		}
	}
}

// The feed is root's: the sink creates it 0600 in a 0700 directory, so the
// run user can neither write nor read it, and the sink marks the feed done
// only after its last event.
func TestSink_FeedIsRootOnlyAndMarkedDoneLast(t *testing.T) {
	cfg, send, stop := startSink(t, nil)
	if err := send(&pb.AgentCommandEvent{Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_START, ToolUseId: "t1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(DonePath(cfg.EventsPath)); err == nil {
		t.Fatal("feed marked done while the sink is still serving")
	}
	stop()
	for path, want := range map[string]os.FileMode{cfg.EventsPath: 0o600, filepath.Dir(cfg.EventsPath): 0o700, DonePath(cfg.EventsPath): 0o600} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", path, fi.Mode().Perm(), want)
		}
	}
}
