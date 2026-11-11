package boxlogs

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeTailer answers with canned windows in order and records requests.
type fakeTailer struct {
	resps []*pb.TailBoxLogsResponse
	reqs  []*pb.TailBoxLogsRequest
}

func (f *fakeTailer) TailBoxLogs(req *pb.TailBoxLogsRequest) (*pb.TailBoxLogsResponse, error) {
	f.reqs = append(f.reqs, req)
	if len(f.reqs) > len(f.resps) {
		return nil, errors.New("no more windows")
	}
	return f.resps[len(f.reqs)-1], nil
}

func okWindow(cursor string, more bool, texts ...string) *pb.TailBoxLogsResponse {
	r := &pb.TailBoxLogsResponse{Status: pb.BoxLogsStatus_BOX_LOGS_STATUS_OK, Cursor: cursor, More: more}
	for i, s := range texts {
		r.Lines = append(r.Lines, &pb.BoxLogLine{Time: timestamppb.New(t0.Add(time.Duration(i) * time.Second)),
			SourceKind: pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_CONTAINER, Source: "web", Text: s})
	}
	return r
}

// Copy hands each window's cursor to the next request and prints every line
// once; without follow it stops at the first window with nothing more.
func TestCopy_FollowsCursor(t *testing.T) {
	f := &fakeTailer{resps: []*pb.TailBoxLogsResponse{okWindow("c1", true, "a", "b"), okWindow("c2", false, "c")}}
	var out bytes.Buffer
	req := &pb.TailBoxLogsRequest{Username: "alice", Tail: 5, Units: []string{"nginx"}, Containers: []string{"web"}}
	cursor, err := Copy(context.Background(), f, req, &out, false)
	if err != nil {
		t.Fatal(err)
	}
	if cursor != "c2" || len(f.reqs) != 2 {
		t.Fatalf("cursor %q after %d requests", cursor, len(f.reqs))
	}
	if r := f.reqs[1]; r.GetCursor() != "c1" || r.GetTail() != 0 || r.GetSince() != nil || len(r.GetUnits()) != 1 || len(r.GetContainers()) != 1 {
		t.Errorf("second request = %v", r)
	}
	if req.GetFollowSeconds() != 0 {
		t.Error("Copy changed the caller's request")
	}
	want := "2026-11-11T12:00:00Z container/web a\n2026-11-11T12:00:01Z container/web b\n2026-11-11T12:00:00Z container/web c\n"
	if out.String() != want {
		t.Errorf("output =\n%s\nwant\n%s", out.String(), want)
	}
}

func TestCopy_FollowUntilCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// Empty, not-more windows: without follow Copy would stop after one.
	f := &cancelTailer{cancelAt: 3, cancel: cancel}
	cursor, err := Copy(ctx, f, &pb.TailBoxLogsRequest{Username: "alice"}, &bytes.Buffer{}, true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(f.reqs) != 3 || cursor != "c3" {
		t.Errorf("%d requests, cursor %q", len(f.reqs), cursor)
	}
	for _, r := range f.reqs {
		if r.GetFollowSeconds() != FollowSeconds {
			t.Errorf("follow request without follow_seconds: %v", r)
		}
	}
}

type cancelTailer struct {
	cancelAt int
	cancel   func()
	reqs     []*pb.TailBoxLogsRequest
}

func (c *cancelTailer) TailBoxLogs(req *pb.TailBoxLogsRequest) (*pb.TailBoxLogsResponse, error) {
	c.reqs = append(c.reqs, req)
	if len(c.reqs) == c.cancelAt {
		c.cancel()
	}
	return okWindow("c"+string(rune('0'+len(c.reqs))), false), nil
}

// A stopped box or an unsupported runtime is a typed error, not an empty
// success.
func TestFetch_StatusError(t *testing.T) {
	f := &fakeTailer{resps: []*pb.TailBoxLogsResponse{{Status: pb.BoxLogsStatus_BOX_LOGS_STATUS_RUNTIME_UNSUPPORTED, Reason: "podman", Runtime: pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_PODMAN}}}
	_, err := Copy(context.Background(), f, &pb.TailBoxLogsRequest{Username: "alice"}, &bytes.Buffer{}, false)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != pb.BoxLogsStatus_BOX_LOGS_STATUS_RUNTIME_UNSUPPORTED {
		t.Fatalf("err = %v, want a RUNTIME_UNSUPPORTED StatusError", err)
	}
}

func TestPath(t *testing.T) {
	p := Path(&pb.TailBoxLogsRequest{Username: "alice", Cursor: "abc", Since: timestamppb.New(t0), Tail: 7,
		Units: []string{"a", "b"}, Containers: []string{"web"}, MaxLines: 50, FollowSeconds: 3})
	u, err := url.Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Path != "/v1/containers/alice/logs" || q.Get("cursor") != "abc" || q.Get("since") != "2026-11-11T12:00:00Z" || q.Get("tail") != "7" ||
		len(q["units"]) != 2 || q.Get("containers") != "web" || q.Get("max_lines") != "50" || q.Get("follow_seconds") != "3" {
		t.Errorf("path = %s", p)
	}
	if Path(&pb.TailBoxLogsRequest{Username: "alice"}) != "/v1/containers/alice/logs" {
		t.Error("empty query not omitted")
	}
}
