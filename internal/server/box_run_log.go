package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/agentbox"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/internal/logframe"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The daemon-side reader over a box's `code run` records (#2123): the
// TailRunLog contract (#2096) for the durable run records and logs agent-box
// keeps under /tmp/agent-box (#1672/#1674).
//
// It only ever reads. Records and logs keep the lifecycle agent-box gives
// them — rotated aside when a later run reuses the name, gone when /tmp is
// cleared — and nothing here writes, moves, or deletes them.
//
// The reader execs as root inside a box whose user owns those files, so it
// opens each one only if it is a regular file whose resolved path is exactly
// the one asked for: a symlink planted by the box's user (a collaborator
// without sudo, say) cannot turn it into a root read of another file.

// boxRunMaxFrameLine bounds one framed-log line: agent-box's framer reads
// 32 KiB at a time, which base64-encodes to 43692 bytes plus "<s> " and "\n".
// A framed read always asks for at least this much, so a whole frame fits.
const boxRunMaxFrameLine = 64 * 1024

// collaboratorCheckFunc reports whether subject is a collaborator on owner's
// box.
type collaboratorCheckFunc func(owner, subject string) (bool, error)

// boxRunOpenFn is the shell helper every script uses to open a box file on
// fd 3: regular file, not a symlink, and resolving to exactly the path given.
const boxRunOpenFn = `open3() {
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  command exec 3<"$1" 2>/dev/null || return 1
  if [ "$(readlink /proc/$$/fd/3)" = "$1" ] && [ -f /proc/$$/fd/3 ]; then return 0; fi
  exec 3<&-
  return 1
}
b64_3() { base64 <&3 | tr -d '\n'; exec 3<&-; }
`

// boxRunListScript prints "B <boot-id>", "P <live pids>", then one
// "R <file> <base64 record> <base64 exit sidecar | ->" line per record file.
func boxRunListScript(dir string) string {
	return fmt.Sprintf(`d=%s
%s[ -d "$d" ] || exit 0
echo "B $(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
echo "P $(ls /proc | grep -E '^[0-9]+$' | tr '\n' ' ')"
for f in "$d"/*.json; do
  open3 "$f" || continue
  r=$(b64_3)
  x=-
  if open3 "${f%%.json}.exit"; then x=$(b64_3); fi
  echo "R ${f##*/} ${r:--} ${x:--}"
done
`, shellSingleQuote(dir), boxRunOpenFn)
}

// boxRunTailScript prints the run's record ("R <base64>" or "missing"), its
// exit sidecar ("X <base64 | ->"), then the log's state — "L none",
// "L unsafe", or "L <size>" followed by up to limit bytes from offset. The
// outcome is read before the size, so a run seen as exited has a complete
// log.
func boxRunTailScript(dir, name string, offset int64, limit int) string {
	return fmt.Sprintf(`d=%s
n=%s
%sif open3 "$d/$n.json"; then echo "R $(b64_3)"; else echo missing; exit 0; fi
if open3 "$d/$n.exit"; then echo "X $(b64_3)"; else echo "X -"; fi
l="$d/$n.log"
if [ ! -e "$l" ] && [ ! -L "$l" ]; then echo "L none"; exit 0; fi
open3 "$l" || { echo "L unsafe"; exit 0; }
echo "L $(stat -L -c %%s /proc/$$/fd/3)"
tail -c +%d <&3 | head -c %d
`, shellSingleQuote(dir), shellSingleQuote(name), boxRunOpenFn, offset+1, limit)
}

// boxRunView is one record as the reader sees it.
type boxRunView struct {
	fileName string
	record   agentbox.RunRecord
}

func decodeB64Field(s string) ([]byte, error) {
	if s == "-" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// parseBoxRunList turns the list script's output into protos, newest first.
// A record that does not decode, or whose file name is not a valid run name,
// is skipped: one bad file must not hide every other run.
func parseBoxRunList(out, dir string) []*pb.BoxRun {
	var boot string
	alive := map[int]bool{}
	var views []boxRunView
	for _, line := range strings.Split(out, "\n") {
		kind, rest, _ := strings.Cut(line, " ")
		switch kind {
		case "B":
			boot = strings.TrimSpace(rest)
		case "P":
			for _, f := range strings.Fields(rest) {
				if pid, err := strconv.Atoi(f); err == nil {
					alive[pid] = true
				}
			}
		case "R":
			fields := strings.Fields(rest)
			if len(fields) != 3 || !agentbox.IsCurrentRecordFile(fields[0]) {
				continue
			}
			name := strings.TrimSuffix(fields[0], ".json")
			if !validRunPathID(name) {
				continue
			}
			recData, err := decodeB64Field(fields[1])
			if err != nil {
				continue
			}
			record, err := agentbox.DecodeRunRecord(recData)
			if err != nil {
				continue
			}
			sidecar, err := decodeB64Field(fields[2])
			if err != nil {
				sidecar = nil
			}
			views = append(views, boxRunView{fileName: name, record: agentbox.FoldExitSidecar(record, sidecar)})
		}
	}
	sort.SliceStable(views, func(i, j int) bool {
		a, b := views[i].record.StartedAt, views[j].record.StartedAt
		if !a.Equal(b) {
			return a.After(b)
		}
		return views[i].fileName < views[j].fileName
	})
	runs := make([]*pb.BoxRun, 0, len(views))
	for _, v := range views {
		outcome := agentbox.ResolveOutcome(v.record, boot, func(pid int) bool { return pid > 0 && alive[pid] })
		runs = append(runs, boxRunProto(v.fileName, dir, v.record, outcome))
	}
	return runs
}

func boxRunProto(name, dir string, r agentbox.RunRecord, outcome agentbox.RunOutcome) *pb.BoxRun {
	run := &pb.BoxRun{
		RunName:     name,
		StartedAt:   timestamppb.New(r.StartedAt),
		LogPath:     boxRunLogPath(dir, name),
		CaptureMode: pb.CaptureMode_CAPTURE_MODE_COMBINED,
	}
	if r.CaptureMode == agentbox.CaptureFramed {
		run.CaptureMode = pb.CaptureMode_CAPTURE_MODE_FRAMED
	}
	switch outcome {
	case agentbox.RunOutcomeRunning:
		run.Outcome = pb.BoxRunOutcome_BOX_RUN_OUTCOME_RUNNING
	case agentbox.RunOutcomeExited:
		run.Outcome = pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED
	default:
		run.Outcome = pb.BoxRunOutcome_BOX_RUN_OUTCOME_UNKNOWN
	}
	if r.ExitCode != nil {
		code := int32(*r.ExitCode) // #nosec G115 -- a process exit status fits in int32
		run.ExitCode = &code
	}
	if r.FinishedAt != nil {
		run.EndedAt = timestamppb.New(*r.FinishedAt)
	}
	return run
}

// boxRunLogPath is the log the reader reads: always derived from the run
// name, never the record's own log_path, which the box's user can write.
func boxRunLogPath(dir, name string) string { return dir + "/" + name + ".log" }

// boxRunWindow is one read of a run's record and log.
type boxRunWindow struct {
	found   bool
	record  agentbox.RunRecord
	logSeen bool   // the log file exists
	unsafe  bool   // the log is not a plain file at its own path
	size    int64  // the log's size, read after the record
	raw     []byte // up to limit bytes from the offset
}

func readBoxRunWindow(exec boxScriptFunc, box, dir, name string, offset int64, limit int) (boxRunWindow, error) {
	out, err := exec(box, boxRunTailScript(dir, name, offset, limit))
	if err != nil {
		return boxRunWindow{}, err
	}
	recLine, rest, _ := strings.Cut(out, "\n")
	if recLine == "missing" {
		return boxRunWindow{}, nil
	}
	exitLine, rest, _ := strings.Cut(rest, "\n")
	logLine, rest, found := strings.Cut(rest, "\n")
	recB64, okR := strings.CutPrefix(recLine, "R ")
	exitB64, okX := strings.CutPrefix(exitLine, "X ")
	logState, okL := strings.CutPrefix(logLine, "L ")
	if !okR || !okX || !okL || !found {
		return boxRunWindow{}, fmt.Errorf("unexpected run read output %q", strings.Join([]string{recLine, exitLine, logLine}, " | "))
	}
	recData, err := decodeB64Field(recB64)
	if err != nil {
		return boxRunWindow{}, fmt.Errorf("decode run record: %w", err)
	}
	record, err := agentbox.DecodeRunRecord(recData)
	if err != nil {
		return boxRunWindow{}, status.Errorf(codes.FailedPrecondition, "run %q: %v", name, err)
	}
	sidecar, _ := decodeB64Field(exitB64)
	w := boxRunWindow{found: true, record: agentbox.FoldExitSidecar(record, sidecar)}
	switch logState {
	case "none":
		return w, nil
	case "unsafe":
		w.unsafe = true
		return w, nil
	}
	w.size, err = strconv.ParseInt(strings.TrimSpace(logState), 10, 64)
	if err != nil {
		return boxRunWindow{}, fmt.Errorf("unexpected log size %q", logState)
	}
	w.logSeen, w.raw = true, []byte(rest)
	return w, nil
}

// boxRunResponse turns one read into the response. A combined log is served
// as-is, like TailRunLog. A framed log is consumed whole frames at a time —
// at least one, then as many more as fit in maxBytes — with stdout payloads
// in chunk and stderr frames dropped and flagged. ended is set only once the
// run has an exit code and the reader has reached the end of its log.
func boxRunResponse(w boxRunWindow, offset int64, maxBytes, readLimit int) (*pb.TailBoxRunLogResponse, error) {
	resp := &pb.TailBoxRunLogResponse{EndOffset: offset}
	exited := w.record.ExitCode != nil
	if w.record.CaptureMode != agentbox.CaptureFramed {
		chunk := w.raw
		if len(chunk) > maxBytes {
			chunk, resp.Truncated = chunk[:maxBytes], true
		}
		resp.Chunk = chunk
		resp.EndOffset = offset + int64(len(chunk))
	} else {
		var demux logframe.Demuxer
		consumed, stopped := 0, false
		for {
			i := bytes.IndexByte(w.raw[consumed:], '\n')
			if i < 0 {
				break
			}
			line := w.raw[consumed : consumed+i+1]
			if consumed > 0 && consumed+len(line) > maxBytes {
				stopped = true
				break
			}
			frames, err := demux.Write(line)
			if err != nil {
				if consumed == 0 && offset > 0 {
					return nil, status.Errorf(codes.InvalidArgument, "start_offset %d is not at a frame boundary of this framed log", offset)
				}
				return nil, status.Errorf(codes.DataLoss, "framed log at offset %d: %v", offset+int64(consumed), err)
			}
			for _, f := range frames {
				if f.Stream == logframe.Stdout {
					resp.Chunk = append(resp.Chunk, f.Payload...)
				} else {
					resp.StderrDropped = true
				}
			}
			consumed += len(line)
		}
		resp.EndOffset = offset + int64(consumed)
		resp.Truncated = stopped || (len(w.raw) >= readLimit && consumed < len(w.raw))
	}
	resp.Ended = exited && !resp.Truncated && resp.EndOffset >= w.size
	return resp, nil
}

// boxRunExecFn returns the exec seam: the injected fake, else the container
// manager.
func (s *ContainerServer) boxRunExecFn() boxScriptFunc {
	if s.boxRunExec != nil {
		return s.boxRunExec
	}
	if s.manager == nil {
		return nil
	}
	mgr := s.manager
	return func(box, script string) (string, error) {
		out, stderr, code, err := mgr.ExecWithExitCode(box, []string{"sh", "-c", script})
		if err != nil {
			return "", err
		}
		if code != 0 {
			return "", fmt.Errorf("exit %d: %s", code, strings.TrimSpace(stderr))
		}
		return out, nil
	}
}

func (s *ContainerServer) boxRunDir() string {
	if s.boxRunLogDir != "" {
		return s.boxRunLogDir
	}
	return agentbox.DefaultLogDir
}

// authorizeBoxRuns is the access check for both RPCs: the same ssh:write
// scope connecting to the box (AddSSHKey) needs, held by the box's owner (or
// an admin) or by one of the box's collaborators.
func (s *ContainerServer) authorizeBoxRuns(ctx context.Context, owner string) error {
	if err := auth.RequireScope(ctx, auth.ScopeSSHWrite); err != nil {
		return err
	}
	if auth.AuthorizeTenant(ctx, owner) == nil {
		return nil
	}
	subject, _, _ := auth.SubjectFromGRPCContext(ctx)
	check := s.boxRunCollaborator
	if check == nil && s.collaboratorManager != nil {
		check = func(owner, subject string) (bool, error) {
			_, err := s.collaboratorManager.GetCollaborator(owner, subject)
			if errors.Is(err, collaborator.ErrNotFound) {
				return false, nil
			}
			return err == nil, err
		}
	}
	if check != nil {
		ok, err := check(owner, subject)
		if err != nil {
			return status.Errorf(codes.Internal, "look up collaborators of %q: %v", owner, err)
		}
		if ok {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "not the box's owner or a collaborator on it")
}

func validateBoxRunOwner(username string) error {
	if !validRunPathID(username) {
		return status.Errorf(codes.InvalidArgument, "username must match %s", runIDPattern.String())
	}
	return nil
}

// ListBoxRuns lists a box's current code-run records (#2123).
func (s *ContainerServer) ListBoxRuns(ctx context.Context, req *pb.ListBoxRunsRequest) (*pb.ListBoxRunsResponse, error) {
	if err := validateBoxRunOwner(req.GetUsername()); err != nil {
		return nil, err
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}
	exec := s.boxRunExecFn()
	if exec == nil {
		return nil, status.Error(codes.Unavailable, "no container backend to read run records from")
	}
	dir := s.boxRunDir()
	out, err := exec(req.GetUsername()+"-container", boxRunListScript(dir))
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read run records of %q: %v", req.GetUsername(), err)
	}
	return &pb.ListBoxRunsResponse{Runs: parseBoxRunList(out, dir)}, nil
}

// TailBoxRunLog returns one byte window of a box run's log (#2123).
func (s *ContainerServer) TailBoxRunLog(ctx context.Context, req *pb.TailBoxRunLogRequest) (*pb.TailBoxRunLogResponse, error) {
	// Both names become paths inside the box: validate before anything
	// else touches them.
	if err := validateBoxRunOwner(req.GetUsername()); err != nil {
		return nil, err
	}
	if !validRunPathID(req.GetRunName()) {
		return nil, status.Errorf(codes.InvalidArgument, "run_name must match %s and not be . or ..", runIDPattern.String())
	}
	if req.GetStartOffset() < 0 {
		return nil, status.Error(codes.InvalidArgument, "start_offset must be >= 0")
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}
	maxBytes := int(req.GetMaxBytes())
	switch {
	case maxBytes <= 0:
		maxBytes = tailRunLogDefaultBytes
	case maxBytes > tailRunLogMaxBytes:
		maxBytes = tailRunLogMaxBytes
	}
	follow := time.Duration(min(max(req.GetFollowSeconds(), 0), tailRunLogMaxFollow)) * time.Second
	exec := s.boxRunExecFn()
	if exec == nil {
		return nil, status.Error(codes.Unavailable, "no container backend to read the log from")
	}
	poll := s.boxRunPoll
	if poll <= 0 {
		poll = tailRunLogPoll
	}

	box, dir, name, offset := req.GetUsername()+"-container", s.boxRunDir(), req.GetRunName(), req.GetStartOffset()
	// One extra byte tells a full window from a truncated one; a framed log
	// is read at least one whole frame deep.
	readLimit := maxBytes + 1
	deadline := time.Now().Add(follow)
	for {
		w, err := readBoxRunWindow(exec, box, dir, name, offset, max(readLimit, boxRunMaxFrameLine+1))
		if err != nil {
			if _, ok := status.FromError(err); ok && status.Code(err) != codes.Unknown {
				return nil, err
			}
			return nil, status.Errorf(codes.Unavailable, "read run %q on %s: %v", name, box, err)
		}
		if !w.found {
			return nil, status.Errorf(codes.NotFound, "run %q not found on %s's box", name, req.GetUsername())
		}
		if w.unsafe {
			return nil, status.Errorf(codes.FailedPrecondition, "run %q: log is not a regular file at %s", name, boxRunLogPath(dir, name))
		}
		if w.record.CaptureMode != agentbox.CaptureFramed && len(w.raw) > readLimit {
			w.raw = w.raw[:readLimit]
		}
		limit := readLimit
		if w.record.CaptureMode == agentbox.CaptureFramed {
			limit = max(readLimit, boxRunMaxFrameLine+1)
		}
		resp, err := boxRunResponse(w, offset, maxBytes, limit)
		if err != nil {
			return nil, err
		}
		if resp.EndOffset != offset || resp.Ended || !time.Now().Add(poll).Before(deadline) {
			return resp, nil
		}
		select {
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		case <-time.After(poll):
		}
	}
}
