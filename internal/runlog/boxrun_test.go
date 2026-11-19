package runlog

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// stderrTailer serves log in two windows and records every request. echo is
// the stream it reports having read: what a daemon with box_run_stderr
// answers, or UNSPECIFIED for one without it.
type stderrTailer struct {
	log  []byte
	echo pb.BoxRunLogStream
	reqs []*pb.TailBoxRunLogRequest
}

func (f *stderrTailer) TailBoxRunLog(req *pb.TailBoxRunLogRequest) (*pb.TailBoxRunLogResponse, error) {
	f.reqs = append(f.reqs, req)
	start := req.GetStartOffset()
	end := min(start+4, int64(len(f.log)))
	return &pb.TailBoxRunLogResponse{
		Chunk:     f.log[start:end],
		EndOffset: end,
		Ended:     end == int64(len(f.log)),
		Stream:    f.echo,
	}, nil
}

// #3757: every window of a stderr read asks for the stderr log, and the
// output is that log byte for byte.
func TestCopyBox_StderrKeepsTheStreamOnEveryWindow(t *testing.T) {
	f := &stderrTailer{log: []byte("Error: expired\n"), echo: pb.BoxRunLogStream_BOX_RUN_LOG_STREAM_STDERR}
	var out bytes.Buffer
	req := &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task", Stream: pb.BoxRunLogStream_BOX_RUN_LOG_STREAM_STDERR}
	if _, _, err := CopyBox(context.Background(), f, req, &out, true); err != nil {
		t.Fatal(err)
	}
	if out.String() != "Error: expired\n" {
		t.Errorf("output = %q, want the stderr log", out.String())
	}
	if len(f.reqs) < 2 {
		t.Fatalf("%d requests, want several windows", len(f.reqs))
	}
	for i, r := range f.reqs {
		if r.GetStream() != pb.BoxRunLogStream_BOX_RUN_LOG_STREAM_STDERR {
			t.Errorf("request %d stream = %v, want STDERR", i, r.GetStream())
		}
	}
}

// A daemon without box_run_stderr ignores the field and serves the run's
// log. That window is refused, and none of its bytes reach the output.
func TestBoxWindow_RefusesAStderrReadTheDaemonIgnored(t *testing.T) {
	f := &stderrTailer{log: []byte(`{"type":"result"}`)}
	req := &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task", Stream: pb.BoxRunLogStream_BOX_RUN_LOG_STREAM_STDERR}
	resp, err := BoxWindow(f, req)
	if !errors.Is(err, ErrBoxRunStderrUnsupported) || resp != nil {
		t.Fatalf("BoxWindow = %v, %v; want ErrBoxRunStderrUnsupported and no window", resp, err)
	}
	var out bytes.Buffer
	if _, _, err := CopyBox(context.Background(), f, req, &out, false); !errors.Is(err, ErrBoxRunStderrUnsupported) || out.Len() != 0 {
		t.Errorf("CopyBox wrote %q, err %v; want nothing and ErrBoxRunStderrUnsupported", out.String(), err)
	}
}

// A read of the run's log is decided as before, whatever the daemon echoes.
func TestBoxWindow_LogReadIgnoresTheEcho(t *testing.T) {
	for _, stream := range []pb.BoxRunLogStream{pb.BoxRunLogStream_BOX_RUN_LOG_STREAM_UNSPECIFIED, pb.BoxRunLogStream_BOX_RUN_LOG_STREAM_LOG} {
		f := &stderrTailer{log: []byte("hi\n")}
		resp, err := BoxWindow(f, &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task", Stream: stream})
		if err != nil || string(resp.GetChunk()) != "hi\n" {
			t.Errorf("stream %v: BoxWindow = %v, %v; want the log", stream, resp, err)
		}
	}
}

// The REST query carries stream by its enum name, and only when it is not
// the default, so a plain read's URL is unchanged.
func TestBoxQuery_Stream(t *testing.T) {
	plain := BoxQuery(&pb.TailBoxRunLogRequest{Username: "alice", RunName: "task", StartOffset: 3})
	if plain != "/v1/containers/alice/code-runs/task/log?start_offset=3" {
		t.Errorf("plain query = %q", plain)
	}
	q := BoxQuery(&pb.TailBoxRunLogRequest{Username: "alice", RunName: "task", Stream: pb.BoxRunLogStream_BOX_RUN_LOG_STREAM_STDERR})
	u, err := url.Parse(q)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("stream"); got != "BOX_RUN_LOG_STREAM_STDERR" {
		t.Errorf("stream = %q in %q, want BOX_RUN_LOG_STREAM_STDERR", got, q)
	}
}
