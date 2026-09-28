// Package runlog is the client side of TailRunLog (#2096): the one Go
// function `containarium crew logs` and the MCP `crew_logs` tool both call.
package runlog

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// FollowSeconds is how long each --follow call lets the daemon wait for new
// bytes (the RPC's upper bound).
const FollowSeconds = 10

// Tailer is the one RPC this package needs; the gRPC, HTTP and MCP clients
// all satisfy it.
type Tailer interface {
	TailRunLog(req *pb.TailRunLogRequest) (*pb.TailRunLogResponse, error)
}

// Window reads one bounded window of a run's journal: the MCP tool's shape,
// and the tail_log contract (pass EndOffset back to resume).
func Window(t Tailer, req *pb.TailRunLogRequest) (*pb.TailRunLogResponse, error) {
	resp, err := t.TailRunLog(req)
	if err != nil {
		return nil, fmt.Errorf("tail run %s from offset %d: %w", req.GetRunId(), req.GetStartOffset(), err)
	}
	return resp, nil
}

// Copy writes the journal from req.StartOffset to w, window by window, and
// returns the offset it reached. With follow it keeps asking (each call
// waiting up to FollowSeconds for new bytes) until the journal says the run
// ended or ctx is done; without it, it stops at the current end of the file.
// Every byte is written exactly once: each call resumes at the previous
// window's end offset.
func Copy(ctx context.Context, t Tailer, req *pb.TailRunLogRequest, w io.Writer, follow bool) (int64, error) {
	offset := req.GetStartOffset()
	for {
		if err := ctx.Err(); err != nil {
			return offset, err
		}
		next := &pb.TailRunLogRequest{RunId: req.GetRunId(), SkillId: req.GetSkillId(), StartOffset: offset, MaxBytes: req.GetMaxBytes()}
		if follow {
			next.FollowSeconds = FollowSeconds
		}
		resp, err := Window(t, next)
		if err != nil {
			return offset, err
		}
		if _, err := w.Write(resp.GetChunk()); err != nil {
			return offset, err
		}
		offset = resp.GetEndOffset()
		if resp.GetEnded() || (!follow && !resp.GetTruncated()) {
			return offset, nil
		}
	}
}

// Query renders req as the REST query string for GET /v1/agent-runs/{run_id}/log.
func Query(req *pb.TailRunLogRequest) string {
	q := url.Values{}
	if req.GetSkillId() != "" {
		q.Set("skill_id", req.GetSkillId())
	}
	if req.GetStartOffset() != 0 {
		q.Set("start_offset", strconv.FormatInt(req.GetStartOffset(), 10))
	}
	if req.GetMaxBytes() != 0 {
		q.Set("max_bytes", strconv.Itoa(int(req.GetMaxBytes())))
	}
	if req.GetFollowSeconds() != 0 {
		q.Set("follow_seconds", strconv.Itoa(int(req.GetFollowSeconds())))
	}
	return "/v1/agent-runs/" + url.PathEscape(req.GetRunId()) + "/log?" + q.Encode()
}
