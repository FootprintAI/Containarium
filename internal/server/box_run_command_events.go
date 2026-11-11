package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/runhook"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The command event feed (#3582): a read-only view of the audit file a run's
// root-run sink wrote. The file is the sink's alone (root-owned 0600 in a 0700
// directory the run user cannot enter), one event per line with seq equal to
// the line number, so a page is "lines after_seq+1 .. after_seq+limit".

const (
	// commandEventsDefaultLimit is the page size when limit is 0, and the
	// largest page.
	commandEventsDefaultLimit = 500
	// commandEventsReadCap bounds the bytes one read ships back. A page whose
	// lines do not fit is cut at the last whole line: the reader asks again
	// from there.
	commandEventsReadCap = 8 << 20
	// commandEventsMaxAfterSeq keeps after_seq a number the box's tail takes.
	commandEventsMaxAfterSeq = 1 << 53
)

// commandSinkUID is the box user the audit sink runs as: root.
const commandSinkUID = "0"

// commandSinkProbeScript prints "S 1" when a process owned by uid is running
// `run-audit-sink --config <configPath>` (the run's sink, which the launch
// script starts with exactly that configuration), else "S 0". Only a process
// of that user counts, so the run user cannot stand in for the sink. The
// needle is put together in the box: the script's own text, which is in the
// command line of the shell running it, never holds it in one piece.
func commandSinkProbeScript(configPath, uid string) string {
	return fmt.Sprintf(`n=run-audit-sink
c=%s
s=0
for p in $(grep -lsF -- "$c" /proc/[0-9]*/cmdline 2>/dev/null); do
  [ "$(stat -c %%u "${p%%/cmdline}" 2>/dev/null)" = %s ] || continue
  if tr '\0' ' ' <"$p" 2>/dev/null | grep -qF -- " $n --config $c "; then s=1; break; fi
done
echo "S $s"
`, shellSingleQuote(configPath), shellSingleQuote(uid))
}

// commandEventsScript prints sinkProbe's line, if one is given (see
// commandSinkProbeScript), then "D 1" or "D 0" (the sink's done marker), then
// "E -" when the run has no feed, else "E <base64 of the lines after afterSeq>"
// with at most limit+1 lines, so the daemon can tell a page that reaches the
// end from one that does not. The order is what makes each answer final: the
// sink creates the marker after its last event and exits after the marker, so
// a sink seen gone means the marker read after it will not change, and a
// marker seen means the lines read after it are the last.
// Both files open through the same symlink guard as the run reader.
func commandEventsScript(eventsPath string, afterSeq uint64, limit int, sinkProbe string) string {
	return fmt.Sprintf(`%s%sif open3 %s; then echo "D 1"; exec 3<&-; else echo "D 0"; fi
if open3 %s; then
  echo "E $(tail -n +%d <&3 | head -n %d | head -c %d | base64 | tr -d '\n')"; exec 3<&-
else echo "E -"; fi
`, boxRunOpenFn, sinkProbe, shellSingleQuote(runhook.DonePath(eventsPath)), shellSingleQuote(eventsPath),
		afterSeq+1, limit+1, commandEventsReadCap)
}

// commandEventsPage is one read of the feed.
type commandEventsPage struct {
	exists   bool // the run has a feed file
	done     bool // the sink has finished
	sinkGone bool // the sink was looked for and is not running
	lines    [][]byte
	cut      bool // the byte cap stopped the read before limit+1 lines
}

// commandFeedState is the state of a feed as of one page: more is whether
// events are waiting past the page, running whether the run is.
//
// ENDED keeps its one meaning: the sink finished (or the run never had one
// and has stopped). A run that has stopped is not enough to end a feed that
// has a sink, because the sink writes its closing events after the run
// exits. INCOMPLETE is the feed that can no longer end: the run has stopped,
// the sink is gone, and it left no done marker.
func commandFeedState(p commandEventsPage, running, more bool) pb.RunCommandFeedState {
	switch {
	case more:
		return pb.RunCommandFeedState_RUN_COMMAND_FEED_STATE_OPEN
	case p.done || (!p.exists && !running):
		return pb.RunCommandFeedState_RUN_COMMAND_FEED_STATE_ENDED
	case p.exists && !running && p.sinkGone:
		return pb.RunCommandFeedState_RUN_COMMAND_FEED_STATE_INCOMPLETE
	}
	return pb.RunCommandFeedState_RUN_COMMAND_FEED_STATE_OPEN
}

func parseCommandEventsOutput(out string) (commandEventsPage, error) {
	var p commandEventsPage
	sawE := false
	for _, line := range strings.Split(out, "\n") {
		switch {
		case line == "D 1":
			p.done = true
		case line == "D 0":
		case line == "S 0":
			p.sinkGone = true
		case line == "S 1":
		case line == "E -":
			sawE = true
		case strings.HasPrefix(line, "E "):
			sawE, p.exists = true, true
			raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "E "))
			if err != nil {
				return p, fmt.Errorf("decode: %w", err)
			}
			p.cut = len(raw) >= commandEventsReadCap
			// Only whole lines count: a trailing piece without its newline is
			// a cut read (or a write in flight), never an event.
			for len(raw) > 0 {
				i := bytes.IndexByte(raw, '\n')
				if i < 0 {
					break
				}
				p.lines = append(p.lines, raw[:i])
				raw = raw[i+1:]
			}
		}
	}
	if !sawE {
		return p, fmt.Errorf("no reply from the box")
	}
	return p, nil
}

// ListRunCommandEvents reads a box run's command events after a sequence
// number. Same access as ListRunInputs; it never writes.
func (s *ContainerServer) ListRunCommandEvents(ctx context.Context, req *pb.ListRunCommandEventsRequest) (*pb.ListRunCommandEventsResponse, error) {
	if err := validateBoxRunOwner(req.GetUsername()); err != nil {
		return nil, err
	}
	name := req.GetRunName()
	if !validRunPathID(name) {
		return nil, status.Errorf(codes.InvalidArgument, "run_name %q is not a valid run name", name)
	}
	limit := int(req.GetLimit())
	switch {
	case limit < 0:
		return nil, status.Error(codes.InvalidArgument, "limit must not be negative")
	case limit == 0 || limit > commandEventsDefaultLimit:
		limit = commandEventsDefaultLimit
	}
	after := req.GetAfterSeq()
	if after > commandEventsMaxAfterSeq {
		return nil, status.Errorf(codes.InvalidArgument, "after_seq must not exceed %d", uint64(commandEventsMaxAfterSeq))
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}

	box := req.GetUsername() + "-container"
	running, err := s.boxRunRunning(box, req.GetUsername(), name)
	if err != nil {
		return nil, err
	}
	auditDir := s.boxRunAuditDir
	if auditDir == "" {
		auditDir = runhook.AuditDir
	}
	// Whether the sink is still there only matters once the run has stopped;
	// a running run's feed is open either way, so its polls skip the probe.
	sinkProbe := ""
	if !running {
		sinkProbe = commandSinkProbeScript(runhook.ConfigPath(name), commandSinkUID)
	}
	out, err := s.boxRunExecFn()(box, commandEventsScript(runhook.EventsPathUnder(auditDir, name), after, limit, sinkProbe))
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read the command events of run %q: %v", name, err)
	}
	page, err := parseCommandEventsOutput(out)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the command events of run %q: %v", name, err)
	}

	resp := &pb.ListRunCommandEventsResponse{}
	more := page.cut
	lines := page.lines
	if len(lines) > limit {
		lines, more = lines[:limit], true
	}
	opts := protojson.UnmarshalOptions{DiscardUnknown: true}
	for i, l := range lines {
		var e pb.AgentCommandEvent
		if err := opts.Unmarshal(l, &e); err != nil {
			return nil, status.Errorf(codes.Internal, "command event after seq %d of run %q: %v", after+uint64(i), name, err)
		}
		// The sink numbers its lines and stamps its run's name; anything else
		// is a feed this daemon cannot vouch for.
		if want := after + uint64(i) + 1; e.GetSeq() != want || e.GetRunName() != name {
			return nil, status.Errorf(codes.Internal, "command feed of run %q is inconsistent at seq %d", name, want)
		}
		resp.Events = append(resp.Events, &pb.RunCommandEventEntry{Seq: e.GetSeq(), Event: &e})
	}
	// Ended: no more events can ever come and this page has the last one. A run
	// that was started without a command policy has no sink and no feed; once
	// it is not running that is the end too.
	resp.State = commandFeedState(page, running, more)
	resp.Ended = resp.State == pb.RunCommandFeedState_RUN_COMMAND_FEED_STATE_ENDED
	return resp, nil
}
