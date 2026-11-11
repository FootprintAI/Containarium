package boxlogs

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The client side of TailBoxLogs (#3643), shared by `containarium logs` and
// the MCP box_logs tool: both read through Fetch, so they make the same RPC.

// Tailer is the TailBoxLogs RPC; the gRPC, HTTP and MCP clients satisfy it.
type Tailer interface {
	TailBoxLogs(req *pb.TailBoxLogsRequest) (*pb.TailBoxLogsResponse, error)
}

// FollowSeconds is how long a follow read waits for a line per request.
const FollowSeconds = 10

// StatusError is a window the daemon could not read: the box is stopped, or
// runs its containers on an unsupported runtime.
type StatusError struct {
	Box    string
	Status pb.BoxLogsStatus
	Reason string
}

func (e *StatusError) Error() string {
	switch e.Status {
	case pb.BoxLogsStatus_BOX_LOGS_STATUS_BOX_STOPPED:
		return fmt.Sprintf("%s's box is stopped: %s", e.Box, e.Reason)
	case pb.BoxLogsStatus_BOX_LOGS_STATUS_RUNTIME_UNSUPPORTED:
		return fmt.Sprintf("%s's box: %s", e.Box, e.Reason)
	}
	return fmt.Sprintf("%s's box: %v %s", e.Box, e.Status, e.Reason)
}

// Fetch reads one window. A window the daemon could not read is a
// *StatusError, returned with the response.
func Fetch(t Tailer, req *pb.TailBoxLogsRequest) (*pb.TailBoxLogsResponse, error) {
	resp, err := t.TailBoxLogs(req)
	if err != nil {
		return nil, fmt.Errorf("read logs of %s's box: %w", req.GetUsername(), err)
	}
	if s := resp.GetStatus(); s != pb.BoxLogsStatus_BOX_LOGS_STATUS_OK {
		return resp, &StatusError{Box: req.GetUsername(), Status: s, Reason: resp.GetReason()}
	}
	return resp, nil
}

// Copy writes the box's logs from req to w window by window, every line
// once: it passes each window's cursor to the next. Without follow it stops
// once no more lines are ready; with follow it keeps reading until ctx is
// done. It returns the last cursor, to resume from.
func Copy(ctx context.Context, t Tailer, req *pb.TailBoxLogsRequest, w io.Writer, follow bool) (string, error) {
	next := proto.Clone(req).(*pb.TailBoxLogsRequest)
	cursor := req.GetCursor()
	for {
		if err := ctx.Err(); err != nil {
			return cursor, err
		}
		if follow {
			next.FollowSeconds = FollowSeconds
		}
		resp, err := Fetch(t, next)
		if err != nil {
			return cursor, err
		}
		if err := WriteLines(w, resp.GetLines()); err != nil {
			return cursor, err
		}
		cursor = resp.GetCursor()
		if !follow && !resp.GetMore() {
			return cursor, nil
		}
		next = &pb.TailBoxLogsRequest{
			Username: req.GetUsername(), Cursor: cursor,
			Units: req.GetUnits(), Containers: req.GetContainers(), MaxLines: req.GetMaxLines(),
		}
	}
}

// Label is a line's source as printed: journal/<unit> or container/<name>.
func Label(l *pb.BoxLogLine) string {
	if l.GetSourceKind() == pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_CONTAINER {
		return "container/" + l.GetSource()
	}
	return "journal/" + l.GetSource()
}

// WriteLines prints lines as "<time> <label> <text>", one per line, with
// " [truncated]" after a cut line. The daemon already made the text safe
// to print (no control characters).
func WriteLines(w io.Writer, lines []*pb.BoxLogLine) error {
	for _, l := range lines {
		suffix := ""
		if l.GetTruncated() {
			suffix = " [truncated]"
		}
		if _, err := fmt.Fprintf(w, "%s %s %s%s\n", l.GetTime().AsTime().UTC().Format(time.RFC3339Nano), Label(l), l.GetText(), suffix); err != nil {
			return err
		}
	}
	return nil
}

// WriteWindow renders one window for the MCP tool: a header (cursor, more,
// runtime, dropped frames), "---", then the lines as WriteLines prints them.
func WriteWindow(w io.Writer, resp *pb.TailBoxLogsResponse) error {
	if _, err := fmt.Fprintf(w, "cursor: %s\nmore: %v\nruntime: %s\ndropped_frames: %d\n---\n",
		resp.GetCursor(), resp.GetMore(), runtimeName(resp.GetRuntime()), resp.GetDroppedFrames()); err != nil {
		return err
	}
	return WriteLines(w, resp.GetLines())
}

func runtimeName(rt pb.BoxContainerRuntime) string {
	return strings.ToLower(strings.TrimPrefix(rt.String(), "BOX_CONTAINER_RUNTIME_"))
}

// Path renders req as the REST path and query of TailBoxLogs.
func Path(req *pb.TailBoxLogsRequest) string {
	q := url.Values{}
	if req.GetCursor() != "" {
		q.Set("cursor", req.GetCursor())
	}
	if req.GetSince() != nil {
		q.Set("since", req.GetSince().AsTime().UTC().Format(time.RFC3339Nano))
	}
	if req.GetTail() != 0 {
		q.Set("tail", strconv.Itoa(int(req.GetTail())))
	}
	for _, u := range req.GetUnits() {
		q.Add("units", u)
	}
	for _, c := range req.GetContainers() {
		q.Add("containers", c)
	}
	if req.GetMaxLines() != 0 {
		q.Set("max_lines", strconv.Itoa(int(req.GetMaxLines())))
	}
	if req.GetFollowSeconds() != 0 {
		q.Set("follow_seconds", strconv.Itoa(int(req.GetFollowSeconds())))
	}
	p := "/v1/containers/" + url.PathEscape(req.GetUsername()) + "/logs"
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	return p
}
