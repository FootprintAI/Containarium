package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeBoxRunServer serves a run's log the way TailBoxRunLog does, in
// windows ending at cuts, and records every request.
type fakeBoxRunServer struct {
	log           []byte
	cuts          []int64
	stderrDropped bool
	reqs          []*pb.TailBoxRunLogRequest
	runs          []*pb.BoxRun
	listed        []string
}

func (f *fakeBoxRunServer) TailBoxRunLog(req *pb.TailBoxRunLogRequest) (*pb.TailBoxRunLogResponse, error) {
	f.reqs = append(f.reqs, req)
	start := req.GetStartOffset()
	end := start
	for _, c := range f.cuts {
		if c > start {
			end = c
			break
		}
	}
	return &pb.TailBoxRunLogResponse{
		Chunk:         f.log[start:end],
		EndOffset:     end,
		Ended:         end == int64(len(f.log)),
		StderrDropped: f.stderrDropped,
	}, nil
}

func (f *fakeBoxRunServer) ListBoxRuns(username string) ([]*pb.BoxRun, error) {
	f.listed = append(f.listed, username)
	return f.runs, nil
}

// `code logs --follow` is byte-exact over three windows, the same harness
// `crew logs` is held to (#2096).
func TestCodeLogsFollow_ByteExact(t *testing.T) {
	log := []byte("building...\nhéllo from the agent\ndone\n")
	// The second cut splits a multi-byte rune: output is still the log, byte
	// for byte.
	f := &fakeBoxRunServer{log: log, cuts: []int64{7, 14, int64(len(log))}}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var out, diag bytes.Buffer
	if err := codeLogs(cmd, f, "alice", "task", true, &out, &diag); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), log) {
		t.Errorf("output =\n%q\nwant\n%q", out.Bytes(), log)
	}
	if len(f.reqs) != 3 {
		t.Fatalf("%d requests, want 3 (stop at ended)", len(f.reqs))
	}
	for i, want := range []int64{0, 7, 14} {
		r := f.reqs[i]
		if r.GetStartOffset() != want || r.GetUsername() != "alice" || r.GetRunName() != "task" || r.GetFollowSeconds() == 0 {
			t.Errorf("request %d = %+v, want start_offset %d, follow set", i, r, want)
		}
	}
	if diag.Len() != 0 {
		t.Errorf("diagnostics = %q, want none", diag.String())
	}
}

// Without --follow the reader stops at the current end of the log, and a
// framed run's dropped stderr is noted once, on the diagnostic stream.
func TestCodeLogs_NoFollowNotesDroppedStderr(t *testing.T) {
	log := []byte("partial output\n")
	f := &fakeBoxRunServer{log: append(log, "more"...), cuts: []int64{int64(len(log))}, stderrDropped: true}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var out, diag bytes.Buffer
	if err := codeLogs(cmd, f, "alice", "task", false, &out, &diag); err != nil {
		t.Fatal(err)
	}
	if out.String() != string(log) || len(f.reqs) != 1 || f.reqs[0].GetFollowSeconds() != 0 {
		t.Errorf("out=%q reqs=%v; want one non-follow window", out.String(), f.reqs)
	}
	if strings.Count(diag.String(), "stderr") != 1 {
		t.Errorf("diagnostics = %q, want one stderr note", diag.String())
	}
}

func TestCodeRuns_Table(t *testing.T) {
	start := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	code := int32(2)
	f := &fakeBoxRunServer{runs: []*pb.BoxRun{
		{RunName: "live", StartedAt: timestamppb.New(start), Outcome: pb.BoxRunOutcome_BOX_RUN_OUTCOME_RUNNING, LogPath: "/tmp/agent-box/live.log"},
		{RunName: "done", StartedAt: timestamppb.New(start), EndedAt: timestamppb.New(start.Add(time.Minute)), ExitCode: &code,
			Outcome: pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, LogPath: "/tmp/agent-box/done.log"},
		// #2193: a run whose session id has been discovered prints it.
		{RunName: "sess-7", StartedAt: timestamppb.New(start), Outcome: pb.BoxRunOutcome_BOX_RUN_OUTCOME_RUNNING,
			LogPath: "/tmp/agent-box/sess-7.log", SessionId: "sess-7"},
	}}
	var out bytes.Buffer
	if err := codeRuns(f, "alice", &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(f.listed) != 1 || f.listed[0] != "alice" {
		t.Fatalf("listed %v, want [alice]", f.listed)
	}
	if len(lines) != 4 {
		t.Fatalf("output =\n%s\nwant a header and three rows", out.String())
	}
	for _, want := range [][]string{
		{"NAME", "OUTCOME", "EXIT", "STARTED", "ENDED", "SESSION", "LOG"},
		{"live", "running", "-", "2026-09-28T10:00:00Z", "-", "-", "/tmp/agent-box/live.log"},
		{"done", "exited", "2", "2026-09-28T10:00:00Z", "2026-09-28T10:01:00Z", "-", "/tmp/agent-box/done.log"},
		{"sess-7", "running", "-", "2026-09-28T10:00:00Z", "-", "sess-7", "/tmp/agent-box/sess-7.log"},
	} {
		got := strings.Fields(lines[0])
		lines = lines[1:]
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("row = %v, want %v", got, want)
		}
	}
}

func TestCodeRuns_Empty(t *testing.T) {
	var out bytes.Buffer
	if err := codeRuns(&fakeBoxRunServer{}, "alice", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no code runs") {
		t.Errorf("output = %q, want a no-runs message", out.String())
	}
}
