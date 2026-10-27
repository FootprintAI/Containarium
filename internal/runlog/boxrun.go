package runlog

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Box code runs (#2123): the client side of ListBoxRuns and TailBoxRunLog,
// shared by `containarium code runs|logs` and the MCP code_runs/code_logs
// tools, the way Copy/Window serve `crew logs` and crew_logs.

// BoxTailer is the box-run log RPC; the gRPC, HTTP and MCP clients all
// satisfy it.
type BoxTailer interface {
	TailBoxRunLog(req *pb.TailBoxRunLogRequest) (*pb.TailBoxRunLogResponse, error)
}

// BoxLister is the box-run listing RPC.
type BoxLister interface {
	ListBoxRuns(username string) ([]*pb.BoxRun, error)
}

// BoxWindow reads one bounded window of a box run's log.
func BoxWindow(t BoxTailer, req *pb.TailBoxRunLogRequest) (*pb.TailBoxRunLogResponse, error) {
	resp, err := t.TailBoxRunLog(req)
	if err != nil {
		return nil, fmt.Errorf("tail run %s on %s from offset %d: %w", req.GetRunName(), req.GetUsername(), req.GetStartOffset(), err)
	}
	return resp, nil
}

// CopyBox writes a box run's output from req.StartOffset to w, window by
// window, with Copy's contract: every byte exactly once, and with follow it
// keeps reading until the run has ended or ctx is done. stderrDropped
// reports whether any window skipped a framed log's stderr.
func CopyBox(ctx context.Context, t BoxTailer, req *pb.TailBoxRunLogRequest, w io.Writer, follow bool) (end int64, stderrDropped bool, err error) {
	offset := req.GetStartOffset()
	for {
		if err := ctx.Err(); err != nil {
			return offset, stderrDropped, err
		}
		next := &pb.TailBoxRunLogRequest{Username: req.GetUsername(), RunName: req.GetRunName(), StartOffset: offset, MaxBytes: req.GetMaxBytes()}
		if follow {
			next.FollowSeconds = FollowSeconds
		}
		resp, err := BoxWindow(t, next)
		if err != nil {
			return offset, stderrDropped, err
		}
		if _, err := w.Write(resp.GetChunk()); err != nil {
			return offset, stderrDropped, err
		}
		stderrDropped = stderrDropped || resp.GetStderrDropped()
		offset = resp.GetEndOffset()
		if resp.GetEnded() || (!follow && !resp.GetTruncated()) {
			return offset, stderrDropped, nil
		}
	}
}

// BoxRunsPath is the REST path for ListBoxRuns.
func BoxRunsPath(username string) string {
	return "/v1/containers/" + url.PathEscape(username) + "/code-runs"
}

// BoxQuery renders req as the REST path and query for TailBoxRunLog.
func BoxQuery(req *pb.TailBoxRunLogRequest) string {
	q := url.Values{}
	if req.GetStartOffset() != 0 {
		q.Set("start_offset", strconv.FormatInt(req.GetStartOffset(), 10))
	}
	if req.GetMaxBytes() != 0 {
		q.Set("max_bytes", strconv.Itoa(int(req.GetMaxBytes())))
	}
	if req.GetFollowSeconds() != 0 {
		q.Set("follow_seconds", strconv.Itoa(int(req.GetFollowSeconds())))
	}
	return BoxRunsPath(req.GetUsername()) + "/" + url.PathEscape(req.GetRunName()) + "/log?" + q.Encode()
}

// WriteBoxRuns renders a box's runs as the table `code runs` prints.
func WriteBoxRuns(w io.Writer, username string, runs []*pb.BoxRun) error {
	if len(runs) == 0 {
		_, err := fmt.Fprintf(w, "no code runs on %s's box\n", username)
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tOUTCOME\tEXIT\tSTARTED\tENDED\tSESSION\tLOG")
	for _, r := range runs {
		exit, ended := "-", "-"
		if r.ExitCode != nil {
			exit = strconv.Itoa(int(r.GetExitCode()))
		}
		if r.GetEndedAt() != nil {
			ended = r.GetEndedAt().AsTime().UTC().Format(time.RFC3339)
		}
		// #2193: empty when the engine exposes no session id, or discovery
		// hasn't found one yet for a just-started run — never a guess.
		session := "-"
		if r.GetSessionId() != "" {
			session = r.GetSessionId()
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.GetRunName(), outcomeWord(r.GetOutcome()), exit,
			r.GetStartedAt().AsTime().UTC().Format(time.RFC3339), ended, session, r.GetLogPath())
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return writeBoxRunTools(w, runs)
}

// writeBoxRunTools prints, under the table, the tools the box's own run wrapper measured for
// each run that has any (#2954). The table above is left exactly as it was for anything that
// reads it. These are tools AVAILABLE on the run's PATH, not tools USED.
func writeBoxRunTools(w io.Writer, runs []*pb.BoxRun) error {
	for _, r := range runs {
		if len(r.GetTools()) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "\ntools available to run %s (measured on the box):\n", r.GetRunName()); err != nil {
			return err
		}
		for _, tl := range r.GetTools() {
			version := tl.GetVersion()
			if version == "" {
				version = "(version not reported)"
			}
			if _, err := fmt.Fprintf(w, "  %s  %s  [%s, %s]\n", tl.GetName(), version, toolProvenanceWord(tl.GetProvenance()), toolLocationWord(tl.GetLocation())); err != nil {
				return err
			}
		}
	}
	return nil
}

func toolProvenanceWord(p pb.BoxRunToolProvenance) string {
	switch p {
	case pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_PRESENT_AT_START:
		return "present at start"
	case pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_ADDED_DURING_RUN:
		return "added during the run"
	case pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_CHANGED_DURING_RUN:
		return "changed during the run"
	}
	return "unknown"
}

func toolLocationWord(l pb.BoxRunToolLocation) string {
	switch l {
	case pb.BoxRunToolLocation_BOX_RUN_TOOL_LOCATION_HOME:
		return "run user's home"
	case pb.BoxRunToolLocation_BOX_RUN_TOOL_LOCATION_SYSTEM:
		return "system"
	}
	return "unknown location"
}

func outcomeWord(o pb.BoxRunOutcome) string {
	return strings.ToLower(strings.TrimPrefix(o.String(), "BOX_RUN_OUTCOME_"))
}
