package server

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The run journal's read path (#2096). The in-box runtime appends one
// JSON-lines file per run per member box (#2095, agent-runtime/src/journal.ts);
// TailRunLog serves byte windows of it, resumable by offset.
const (
	// runJournalRoot mirrors journal.ts JOURNAL_ROOT.
	runJournalRoot = "/var/log/agent-runtime/runs"

	tailRunLogDefaultBytes = 65536
	tailRunLogMaxBytes     = 262144
	tailRunLogMaxFollow    = 10
	tailRunLogPoll         = 500 * time.Millisecond

	// runEndedMarker is the prefix of the status line runJournaled writes
	// last ("run ended exit=N"), as JSON.stringify lays out its fields.
	runEndedMarker = `"kind":"status","text":"run ended`
)

// boxScriptFunc runs a POSIX shell script inside a box and returns its stdout.
// A non-zero exit is an error. Production wraps the container manager; tests
// fake it.
type boxScriptFunc func(box, script string) (string, error)

// crewRunMembersFunc resolves a crew run id to its members' skill ids, entry
// skill first. ok=false means no crew run has that id.
type crewRunMembersFunc func(ctx context.Context, runID string) (members []string, ok bool, err error)

// recordSkillRunFunc persists a durable run->skill record for a standalone
// skill run (#2122), via the crew-run record store crew runs already use —
// CrewServer.recordSkillRun in production, wired by NewCrewServer the same
// way crewRunMembers is. Nil is a valid, silent no-op: a daemon (or test)
// with no CrewServer wired just keeps pre-#2122 behavior — the in-memory
// runIndex resolves the run until this process exits, and a restart loses it,
// exactly as before.
type recordSkillRunFunc func(ctx context.Context, runID, skillID string) error

// reapSkillRunFunc removes a standalone skill run's durable record, called by
// the run-journal reaper for every run id whose journal directory it reaps
// (#2122) — crew and skill run ids alike. Implementations must ignore any id
// that names a crew run; CrewServer.reapSkillRunRecord does, via
// CrewRunStore.DeleteSkillRun. Nil is a valid, silent no-op.
type reapSkillRunFunc func(ctx context.Context, runID string) error

// memberBox is the container a skill's box runs in (provisionSkillBox).
func memberBox(skillID string) string { return agentBoxPrefix + skillID + "-container" }

// journalFile is <root>/<run_id>/<skill_id>.jsonl. Both ids must already have
// passed validRunPathID.
func journalFile(runID, skillID string) string {
	return runJournalRoot + "/" + runID + "/" + skillID + ".jsonl"
}

// validRunPathID reports whether id is safe as a single path segment: the
// daemon's runIDPattern, minus "." and "..". Same rule as journal.ts checkId.
func validRunPathID(id string) bool {
	return id != "." && id != ".." && runIDPattern.MatchString(id)
}

// runMemberIndex remembers which skills were provisioned under each run id,
// in provisioning order, so a skill run can still be tailed after its lease
// ends (the run registry forgets it then). In memory only: after a daemon
// restart a skill run's journal is reachable again only through a crew run
// record. Entries older than the journal retention window are dropped.
type runMemberIndex struct {
	mu      sync.Mutex
	members map[string][]string
	added   map[string]time.Time
}

func (x *runMemberIndex) add(runID, skillID string, now time.Time, retention time.Duration) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.members == nil {
		x.members, x.added = map[string][]string{}, map[string]time.Time{}
	}
	for id, t := range x.added {
		if now.Sub(t) > retention {
			delete(x.members, id)
			delete(x.added, id)
		}
	}
	for _, m := range x.members[runID] {
		if m == skillID {
			return
		}
	}
	x.members[runID] = append(x.members[runID], skillID)
	x.added[runID] = now
}

func (x *runMemberIndex) get(runID string) []string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return append([]string(nil), x.members[runID]...)
}

// runMembers resolves a run id to its member skills, entry skill first: a
// crew run from its (durable) run record, else a skill run from the index.
func (s *AgentSkillServer) runMembers(ctx context.Context, runID string) ([]string, error) {
	if s.crewRunMembers != nil {
		members, ok, err := s.crewRunMembers(ctx, runID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "look up run %q: %v", runID, err)
		}
		if ok && len(members) > 0 {
			return members, nil
		}
	}
	if members := s.runIndex.get(runID); len(members) > 0 {
		return members, nil
	}
	return nil, status.Errorf(codes.NotFound, "run %q not found", runID)
}

// boxScript returns the exec seam: the injected fake, else the container
// manager.
func (s *AgentSkillServer) boxScript() boxScriptFunc {
	if s.execScript != nil {
		return s.execScript
	}
	if s.recipes == nil || s.recipes.containers == nil || s.recipes.containers.manager == nil {
		return nil
	}
	mgr := s.recipes.containers.manager
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

// journalWindow is one read of a journal file.
type journalWindow struct {
	exists bool
	size   int64
	// lastEnded: the file's last line is a "run ended" status line.
	lastEnded bool
	// raw holds up to max+1 bytes from the offset; the extra byte only
	// signals truncation.
	raw []byte
}

// journalReadScript reads the file's size and whether its last line is a
// "run ended" status line, then up to limit bytes from offset: never the
// whole file. The first stdout line is "missing" or "<size> <0|1>"; the
// bytes after it are the chunk.
func journalReadScript(path string, offset int64, limit int) string {
	q := shellSingleQuote(path)
	return fmt.Sprintf(`f=%s
[ -f "$f" ] || { echo missing; exit 0; }
size=$(wc -c < "$f" | tr -d ' ')
ended=0
tail -n 1 "$f" | grep -qF %s && ended=1
echo "$size $ended"
tail -c +%d "$f" | head -c %d
`, q, shellSingleQuote(runEndedMarker), offset+1, limit)
}

func readJournalWindow(exec boxScriptFunc, box, path string, offset int64, limit int) (journalWindow, error) {
	out, err := exec(box, journalReadScript(path, offset, limit))
	if err != nil {
		return journalWindow{}, err
	}
	header, rest, found := strings.Cut(out, "\n")
	if header == "missing" {
		return journalWindow{}, nil
	}
	fields := strings.Fields(header)
	if !found || len(fields) != 2 {
		return journalWindow{}, fmt.Errorf("unexpected journal read header %q", header)
	}
	size, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return journalWindow{}, fmt.Errorf("unexpected journal size %q", fields[0])
	}
	return journalWindow{exists: true, size: size, lastEnded: fields[1] == "1", raw: []byte(rest)}, nil
}

// TailRunLog returns one byte window of a run member's journal (#2096).
func (s *AgentSkillServer) TailRunLog(ctx context.Context, req *pb.TailRunLogRequest) (*pb.TailRunLogResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeAgentsRead); err != nil {
		return nil, err
	}
	// Both ids become path segments inside the box: validate before anything
	// else touches them.
	if !validRunPathID(req.GetRunId()) {
		return nil, status.Errorf(codes.InvalidArgument, "run_id must match %s and not be . or ..", runIDPattern.String())
	}
	if req.GetSkillId() != "" && !validRunPathID(req.GetSkillId()) {
		return nil, status.Errorf(codes.InvalidArgument, "skill_id must match %s and not be . or ..", runIDPattern.String())
	}
	if req.GetStartOffset() < 0 {
		return nil, status.Error(codes.InvalidArgument, "start_offset must be >= 0")
	}
	// A run-bound token (an in-box agent) reads only its own run.
	if claim, ok := auth.RunIDFromGRPCContext(ctx); ok && claim != req.GetRunId() {
		return nil, status.Errorf(codes.PermissionDenied, "token is bound to run %q", claim)
	}
	maxBytes := int(req.GetMaxBytes())
	switch {
	case maxBytes <= 0:
		maxBytes = tailRunLogDefaultBytes
	case maxBytes > tailRunLogMaxBytes:
		maxBytes = tailRunLogMaxBytes
	}
	follow := time.Duration(min(max(req.GetFollowSeconds(), 0), tailRunLogMaxFollow)) * time.Second

	members, err := s.runMembers(ctx, req.GetRunId())
	if err != nil {
		return nil, err
	}
	skillID := req.GetSkillId()
	if skillID == "" {
		skillID = members[0]
	} else if !peersContain(members, skillID) {
		return nil, status.Errorf(codes.InvalidArgument, "skill %q is not a member of run %q (members: %s)",
			skillID, req.GetRunId(), strings.Join(members, ","))
	}
	if err := auth.AuthorizeTenant(ctx, agentBoxPrefix+skillID); err != nil {
		return nil, err
	}
	exec := s.boxScript()
	if exec == nil {
		return nil, status.Error(codes.Unavailable, "no container backend to read the journal from")
	}

	path, box := journalFile(req.GetRunId(), skillID), memberBox(skillID)
	offset := req.GetStartOffset()
	poll := s.runLogPoll
	if poll <= 0 {
		poll = tailRunLogPoll
	}
	deadline := time.Now().Add(follow)
	var resp *pb.TailRunLogResponse
	var w journalWindow
	for {
		w, err = readJournalWindow(exec, box, path, offset, maxBytes+1)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "read journal of %q on %s: %v", skillID, box, err)
		}
		resp = windowResponse(w, offset, maxBytes)
		if len(resp.Chunk) > 0 || resp.Ended || !time.Now().Add(poll).Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		case <-time.After(poll):
		}
	}

	for _, m := range members {
		if (m == skillID && w.exists) || (m != skillID && s.journalExists(exec, m, req.GetRunId())) {
			resp.SkillIds = append(resp.SkillIds, m)
		}
	}
	return resp, nil
}

// windowResponse turns one read into the response: at most maxBytes of chunk,
// and ended only once the reader is at the end of a file whose last line is
// "run ended" (so a --follow loop never stops before the last byte).
func windowResponse(w journalWindow, offset int64, maxBytes int) *pb.TailRunLogResponse {
	chunk := w.raw
	truncated := len(chunk) > maxBytes
	if truncated {
		chunk = chunk[:maxBytes]
	}
	end := offset + int64(len(chunk))
	return &pb.TailRunLogResponse{
		Chunk:     chunk,
		EndOffset: end,
		Truncated: truncated,
		Ended:     w.exists && w.lastEnded && !truncated && end >= w.size,
	}
}

func (s *AgentSkillServer) journalExists(exec boxScriptFunc, skillID, runID string) bool {
	out, err := exec(memberBox(skillID), "[ -f "+shellSingleQuote(journalFile(runID, skillID))+" ] && echo yes || true")
	return err == nil && strings.TrimSpace(out) == "yes"
}

// taskRunID decides which run a delegated task is journaled under. A caller
// whose token is bound to a run (an in-box agent) may only journal into that
// run: an absent run_id is stamped with the claim, a different one is
// refused, so one box cannot write into another run's journal. A caller with
// no run claim (the operator driving a crew) keeps what it asked for.
func taskRunID(ctx context.Context, requested string) (string, error) {
	claim, ok := auth.RunIDFromGRPCContext(ctx)
	if !ok || requested == claim {
		return requested, nil
	}
	if requested == "" {
		return claim, nil
	}
	return "", status.Errorf(codes.PermissionDenied, "run_id %q differs from the caller's run %q", requested, claim)
}
