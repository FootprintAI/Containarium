//go:build !containarium_client

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/boxlogs"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const logsID0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var logsT0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

func logsCursor(seq int) string {
	return fmt.Sprintf("s=0123456789abcdef0123456789abcdef;i=%x;b=fedcba9876543210fedcba9876543210;m=%x;t=%x;x=%x", seq, seq, seq, seq)
}

// logsOutput is what the collection script prints for a docker box running
// nginx.service and one container, web, with the given frames.
func logsOutput(frames ...string) string { return logsOutputAt(time.Hour, frames...) }

// logsOutputAt is logsOutput with the box's clock at logsT0+now.
func logsOutputAt(now time.Duration, frames ...string) string {
	head := []string{"V 1", fmt.Sprintf("N %d", logsT0.Add(now).UnixNano()), "R docker",
		"U nginx.service", "C 0 " + logsID0 + " web running", "L 201 201"}
	return strings.Join(append(head, frames...), "\n") + "\n"
}

func logsJournal(seq int, at time.Duration, msg string) string {
	m, _ := json.Marshal(msg)
	return fmt.Sprintf(`J {"__CURSOR":%q,"__REALTIME_TIMESTAMP":"%d","_SYSTEMD_UNIT":"nginx.service","MESSAGE":%s}`,
		logsCursor(seq), logsT0.Add(at).UnixMicro(), m)
}

func logsDocker(at time.Duration, text string) string {
	return "D 0 " + logsT0.Add(at).Format(time.RFC3339Nano) + " " + text
}

// logsBox fakes the box for TailBoxLogs: it records each script exec'd and
// answers with the next canned output (the last one repeats).
type logsBox struct {
	mu      sync.Mutex
	scripts []string
	boxes   []string
	outputs []string
	err     error
}

func (b *logsBox) exec(box, script string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.boxes = append(b.boxes, box)
	b.scripts = append(b.scripts, script)
	if b.err != nil {
		return "", b.err
	}
	return b.outputs[min(len(b.scripts), len(b.outputs))-1], nil
}

func (b *logsBox) calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.scripts)
}

func logsServer(b *logsBox) *ContainerServer {
	return &ContainerServer{
		boxRunExec:   b.exec,
		boxRunPoll:   time.Millisecond,
		boxLogsState: func(string) (bool, error) { return true, nil },
		boxRunCollaborator: func(owner, subject string) (bool, error) {
			return owner == "alice" && subject == "bob", nil
		},
	}
}

func lineStrings(lines []*pb.BoxLogLine) []string {
	var out []string
	for _, l := range lines {
		out = append(out, fmt.Sprintf("%s %s/%s %s", l.GetTime().AsTime().Sub(logsT0), l.GetSourceKind(), l.GetSource(), l.GetText()))
	}
	return out
}

// Criterion 1: one unit and one container come back labelled and in order.
func TestTailBoxLogs_UnitAndContainer(t *testing.T) {
	b := &logsBox{outputs: []string{logsOutput(
		logsJournal(1, 10*time.Millisecond, "nginx started"), logsJournal(2, 30*time.Millisecond, "nginx ready"), "E J 0",
		logsDocker(20*time.Millisecond, "web listening"), "E D 0 0")}}
	s := logsServer(b)
	resp, err := s.TailBoxLogs(tenantCtx("alice"), &pb.TailBoxLogsRequest{Username: "alice", Since: timestamppb.New(logsT0)})
	if err != nil {
		t.Fatalf("TailBoxLogs: %v", err)
	}
	if resp.GetStatus() != pb.BoxLogsStatus_BOX_LOGS_STATUS_OK || resp.GetRuntime() != pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_DOCKER {
		t.Errorf("status %v runtime %v", resp.GetStatus(), resp.GetRuntime())
	}
	want := []string{
		"10ms BOX_LOG_SOURCE_KIND_JOURNAL/nginx.service nginx started",
		"20ms BOX_LOG_SOURCE_KIND_CONTAINER/web web listening",
		"30ms BOX_LOG_SOURCE_KIND_JOURNAL/nginx.service nginx ready",
	}
	if got := lineStrings(resp.GetLines()); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("lines =\n%v\nwant\n%v", got, want)
	}
	if resp.GetCursor() == "" {
		t.Error("no cursor")
	}
	if b.boxes[0] != "alice-container" {
		t.Errorf("exec'd in %q", b.boxes[0])
	}
}

// Criterion 2 at the RPC: the returned cursor is what the next read resumes
// from — the journal after its last line, containers after theirs.
func TestTailBoxLogs_CursorResumes(t *testing.T) {
	b := &logsBox{outputs: []string{
		logsOutputAt(1025*time.Millisecond, logsJournal(1, 10*time.Millisecond, "one"), "E J 0", logsDocker(20*time.Millisecond, "two"), "E D 0 0"),
		logsOutputAt(2*time.Second, logsJournal(3, 40*time.Millisecond, "four"), "E J 0", logsDocker(20*time.Millisecond, "two"), logsDocker(30*time.Millisecond, "three"), "E D 0 0"),
	}}
	s := logsServer(b)
	first, err := s.TailBoxLogs(tenantCtx("alice"), &pb.TailBoxLogsRequest{Username: "alice", Since: timestamppb.New(logsT0)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.TailBoxLogs(tenantCtx("alice"), &pb.TailBoxLogsRequest{Username: "alice", Cursor: first.GetCursor()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.scripts[1], "jcursor='"+logsCursor(1)+"'") {
		t.Errorf("second read does not resume the journal after its last line:\n%s", b.scripts[1][:400])
	}
	// The box answered with "two" again (docker --since is inclusive): the
	// cursor's position skips it.
	got := append(lineStrings(first.GetLines()), lineStrings(second.GetLines())...)
	want := []string{
		"10ms BOX_LOG_SOURCE_KIND_JOURNAL/nginx.service one",
		"20ms BOX_LOG_SOURCE_KIND_CONTAINER/web two",
		"30ms BOX_LOG_SOURCE_KIND_CONTAINER/web three",
		"40ms BOX_LOG_SOURCE_KIND_JOURNAL/nginx.service four",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("lines over two windows =\n%v\nwant\n%v", got, want)
	}
}

// Criterion 3: filters reach the box (units) or the merge (containers), and
// an unknown name is InvalidArgument listing the valid ones.
func TestTailBoxLogs_Filters(t *testing.T) {
	out := logsOutput(logsJournal(1, 10*time.Millisecond, "j"), "E J 0", logsDocker(20*time.Millisecond, "d"), "E D 0 0")
	t.Run("unit", func(t *testing.T) {
		b := &logsBox{outputs: []string{out}}
		resp, err := logsServer(b).TailBoxLogs(tenantCtx("alice"), &pb.TailBoxLogsRequest{Username: "alice", Units: []string{"nginx"}, Tail: 10})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.scripts[0], "units='nginx.service'") || !strings.Contains(b.scripts[0], "dread=0") || !strings.Contains(b.scripts[0], "tail=10") {
			t.Errorf("script parameters:\n%s", b.scripts[0][:400])
		}
		if got := lineStrings(resp.GetLines()); len(got) != 1 || !strings.HasSuffix(got[0], " j") {
			t.Errorf("lines = %v", got)
		}
	})
	t.Run("container", func(t *testing.T) {
		b := &logsBox{outputs: []string{out}}
		resp, err := logsServer(b).TailBoxLogs(tenantCtx("alice"), &pb.TailBoxLogsRequest{Username: "alice", Containers: []string{"web"}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.scripts[0], "jread=0") {
			t.Error("journal read with only a container filter")
		}
		if got := lineStrings(resp.GetLines()); len(got) != 1 || !strings.HasSuffix(got[0], " d") {
			t.Errorf("lines = %v", got)
		}
	})
	for _, tc := range []struct {
		name string
		req  *pb.TailBoxLogsRequest
		want []string
	}{
		{"unknown unit", &pb.TailBoxLogsRequest{Username: "alice", Units: []string{"postgres"}}, []string{"postgres.service", "nginx.service"}},
		{"unknown container", &pb.TailBoxLogsRequest{Username: "alice", Containers: []string{"db"}}, []string{`"db"`, "web"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &logsBox{outputs: []string{out}}
			_, err := logsServer(b).TailBoxLogs(tenantCtx("alice"), tc.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			for _, w := range tc.want {
				if !strings.Contains(status.Convert(err).Message(), w) {
					t.Errorf("%q does not list %s", status.Convert(err).Message(), w)
				}
			}
		})
	}
}

// Anything that would reach the box is validated before any exec.
func TestTailBoxLogs_ValidationBeforeExec(t *testing.T) {
	cases := map[string]*pb.TailBoxLogsRequest{
		"empty username":    {},
		"username slash":    {Username: "a/b"},
		"unit with quote":   {Username: "alice", Units: []string{"a'b"}},
		"unit glob":         {Username: "alice", Units: []string{"*"}},
		"container shell":   {Username: "alice", Containers: []string{"$(id)"}},
		"bad cursor":        {Username: "alice", Cursor: "not-a-cursor!"},
		"cursor and tail":   {Username: "alice", Cursor: boxlogs.EncodeCursor(boxlogs.Cursor{Horizon: 1}), Tail: 3},
		"tail too big":      {Username: "alice", Tail: 5000},
		"negative lines":    {Username: "alice", MaxLines: -1},
		"invalid since":     {Username: "alice", Since: &timestamppb.Timestamp{Seconds: -1 << 60}},
		"since before 1970": {Username: "alice", Since: timestamppb.New(time.Unix(-5, 0))},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			b := &logsBox{outputs: []string{logsOutput()}}
			_, err := logsServer(b).TailBoxLogs(adminCtx(), req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if b.calls() != 0 {
				t.Errorf("%d execs before validation", b.calls())
			}
		})
	}
}

// Criterion 4: a caller without access gets exactly the error TailBoxRunLog
// gives it, and never reaches the box.
func TestTailBoxLogs_AccessMatchesTailBoxRunLog(t *testing.T) {
	cases := []struct {
		name    string
		ctx     context.Context
		allowed bool
	}{
		{"owner", tenantCtx("alice"), true},
		{"admin", adminCtx(), true},
		{"collaborator", tenantCtx("bob"), true},
		{"stranger", tenantCtx("mallory"), false},
		{"owner without ssh:write", scopedCtx("alice", auth.ScopeContainersRead), false},
		{"collaborator without ssh:write", scopedCtx("bob", auth.ScopeContainersRead), false},
		{"unauthenticated", context.Background(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &logsBox{outputs: []string{logsOutput("E J 0", "E D 0 0")}}
			s := logsServer(b)
			_, logsErr := s.TailBoxLogs(tc.ctx, &pb.TailBoxLogsRequest{Username: "alice"})
			if tc.allowed {
				if logsErr != nil {
					t.Fatalf("TailBoxLogs: %v", logsErr)
				}
				return
			}
			runs := &shBox{}
			rs, _ := boxRunServer(t, runs)
			_, runErr := rs.TailBoxRunLog(tc.ctx, &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task"})
			if runErr == nil || status.Code(logsErr) != status.Code(runErr) || status.Convert(logsErr).Message() != status.Convert(runErr).Message() {
				t.Errorf("TailBoxLogs err = %v; TailBoxRunLog err = %v; want the same", logsErr, runErr)
			}
			if b.calls() != 0 {
				t.Errorf("%d execs for a refused caller", b.calls())
			}
		})
	}
}

// A stopped box is reported, not started, and not read.
func TestTailBoxLogs_StoppedBox(t *testing.T) {
	b := &logsBox{outputs: []string{logsOutput()}}
	s := logsServer(b)
	s.boxLogsState = func(string) (bool, error) { return false, nil }
	cursor := boxlogs.EncodeCursor(boxlogs.Cursor{Horizon: 7})
	resp, err := s.TailBoxLogs(tenantCtx("alice"), &pb.TailBoxLogsRequest{Username: "alice", Cursor: cursor})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != pb.BoxLogsStatus_BOX_LOGS_STATUS_BOX_STOPPED || len(resp.GetLines()) != 0 || resp.GetCursor() != cursor {
		t.Errorf("resp = %v", resp)
	}
	if b.calls() != 0 {
		t.Errorf("%d execs on a stopped box", b.calls())
	}
}

func TestTailBoxLogs_BoxErrors(t *testing.T) {
	t.Run("state lookup fails", func(t *testing.T) {
		b := &logsBox{outputs: []string{logsOutput()}}
		s := logsServer(b)
		s.boxLogsState = func(string) (bool, error) { return false, errors.New("backend down") }
		if _, err := s.TailBoxLogs(tenantCtx("alice"), &pb.TailBoxLogsRequest{Username: "alice"}); status.Code(err) != codes.Unavailable {
			t.Fatalf("err = %v, want Unavailable", err)
		}
	})
	t.Run("exec fails", func(t *testing.T) {
		b := &logsBox{err: errors.New("exec broke")}
		if _, err := logsServer(b).TailBoxLogs(tenantCtx("alice"), &pb.TailBoxLogsRequest{Username: "alice"}); status.Code(err) != codes.Unavailable {
			t.Fatalf("err = %v, want Unavailable", err)
		}
	})
	t.Run("output not the script's", func(t *testing.T) {
		b := &logsBox{outputs: []string{"hello\n"}}
		if _, err := logsServer(b).TailBoxLogs(tenantCtx("alice"), &pb.TailBoxLogsRequest{Username: "alice"}); status.Code(err) != codes.Unavailable {
			t.Fatalf("err = %v, want Unavailable", err)
		}
	})
}

// The scoping decision: podman and rootless docker boxes answer
// RUNTIME_UNSUPPORTED, with no partial window.
func TestTailBoxLogs_RuntimeUnsupported(t *testing.T) {
	for _, rt := range []struct {
		word string
		want pb.BoxContainerRuntime
	}{{"podman", pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_PODMAN}, {"docker-rootless", pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_DOCKER_ROOTLESS}} {
		t.Run(rt.word, func(t *testing.T) {
			b := &logsBox{outputs: []string{fmt.Sprintf("V 1\nN %d\nR %s\n", logsT0.UnixNano(), rt.word)}}
			resp, err := logsServer(b).TailBoxLogs(tenantCtx("alice"), &pb.TailBoxLogsRequest{Username: "alice", Units: []string{"nginx"}})
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetStatus() != pb.BoxLogsStatus_BOX_LOGS_STATUS_RUNTIME_UNSUPPORTED || resp.GetRuntime() != rt.want || len(resp.GetLines()) != 0 || resp.GetReason() == "" {
				t.Errorf("resp = %v", resp)
			}
		})
	}
}

// Criterion 5 at the RPC: a hostile box's output cannot break the response
// or push it over its caps.
func TestTailBoxLogs_HostileOutput(t *testing.T) {
	huge := strings.Repeat("A", 1<<20)
	b := &logsBox{outputs: []string{logsOutput(
		logsJournal(1, 10*time.Millisecond, "\x1b]0;pwned\x07ok"), `J {"__CURSOR":"x","MESSAGE":"`+huge+`"}`, "E J 0",
		logsDocker(20*time.Millisecond, huge), logsDocker(30*time.Millisecond, "caf\xe9\x00"), "E D 0 0")}}
	resp, err := logsServer(b).TailBoxLogs(tenantCtx("alice"), &pb.TailBoxLogsRequest{Username: "alice", Since: timestamppb.New(logsT0)})
	if err != nil {
		t.Fatalf("TailBoxLogs: %v", err)
	}
	got := lineStrings(resp.GetLines())
	want := []string{
		"10ms BOX_LOG_SOURCE_KIND_JOURNAL/nginx.service �]0;pwned�ok",
		"30ms BOX_LOG_SOURCE_KIND_CONTAINER/web caf��",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("lines =\n%q\nwant\n%q", got, want)
	}
	if resp.GetDroppedFrames() != 2 {
		t.Errorf("dropped_frames = %d, want 2", resp.GetDroppedFrames())
	}
}

// follow_seconds long-polls like TailBoxRunLog: it waits for a line, and
// gives up with an empty window at the deadline.
func TestTailBoxLogs_Follow(t *testing.T) {
	empty := logsOutputAt(5*time.Millisecond, "E J 0", "E D 0 0")
	t.Run("a line arrives", func(t *testing.T) {
		b := &logsBox{outputs: []string{empty, empty, logsOutput(logsJournal(1, 10*time.Millisecond, "late"), "E J 0", "E D 0 0")}}
		resp, err := logsServer(b).TailBoxLogs(tenantCtx("alice"), &pb.TailBoxLogsRequest{Username: "alice", Since: timestamppb.New(logsT0), FollowSeconds: 5})
		if err != nil {
			t.Fatal(err)
		}
		if got := lineStrings(resp.GetLines()); len(got) != 1 || b.calls() != 3 {
			t.Errorf("lines %v after %d reads", got, b.calls())
		}
	})
	t.Run("deadline", func(t *testing.T) {
		b := &logsBox{outputs: []string{empty}}
		start := time.Now()
		resp, err := logsServer(b).TailBoxLogs(tenantCtx("alice"), &pb.TailBoxLogsRequest{Username: "alice", Since: timestamppb.New(logsT0), FollowSeconds: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.GetLines()) != 0 || resp.GetCursor() == "" {
			t.Errorf("resp = %v", resp)
		}
		if el := time.Since(start); el < 500*time.Millisecond || el > 3*time.Second {
			t.Errorf("follow took %v, want about 1s", el)
		}
	})
}

// The production state seam reads the box's state without starting it.
func TestTailBoxLogs_NoBackend(t *testing.T) {
	s := &ContainerServer{boxRunCollaborator: func(string, string) (bool, error) { return false, nil }}
	if _, err := s.TailBoxLogs(tenantCtx("alice"), &pb.TailBoxLogsRequest{Username: "alice"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
}
