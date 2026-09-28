package server

import (
	"context"
	"fmt"
	"os"
	osexec "os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeBoxes executes the journal scripts against in-memory files, keyed by
// box + path, the way sh would in the box.
type fakeBoxes struct {
	mu    sync.Mutex
	files map[string][]byte
	calls int
	// onRead runs before each journal read (0-based read count), so a test
	// can append between polls.
	onRead func(n int, f *fakeBoxes)
	reads  int
}

var (
	readScriptRE = regexp.MustCompile(`(?s)^f='([^']*)'.*tail -c \+(\d+) "\$f" \| head -c (\d+)`)
	existsRE     = regexp.MustCompile(`^\[ -f '([^']*)' \]`)
)

func (f *fakeBoxes) put(box, path, content string) {
	if f.files == nil {
		f.files = map[string][]byte{}
	}
	f.files[box+":"+path] = []byte(content)
}

func (f *fakeBoxes) exec(box, script string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if m := readScriptRE.FindStringSubmatch(script); m != nil {
		if f.onRead != nil {
			f.onRead(f.reads, f)
		}
		f.reads++
		data, ok := f.files[box+":"+m[1]]
		if !ok {
			return "missing\n", nil
		}
		from, _ := strconv.Atoi(m[2])
		limit, _ := strconv.Atoi(m[3])
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		ended := 0
		if strings.Contains(lines[len(lines)-1], runEndedMarker) {
			ended = 1
		}
		var chunk []byte
		if from-1 < len(data) {
			chunk = data[from-1:]
		}
		if len(chunk) > limit {
			chunk = chunk[:limit]
		}
		return fmt.Sprintf("%d %d\n%s", len(data), ended, chunk), nil
	}
	if m := existsRE.FindStringSubmatch(script); m != nil {
		if _, ok := f.files[box+":"+m[1]]; ok {
			return "yes\n", nil
		}
		return "", nil
	}
	return "", fmt.Errorf("fakeBoxes: unexpected script %q", script)
}

const (
	jStarted   = `{"seq":1,"t":"2026-09-28T00:00:00.000Z","kind":"status","text":"run started"}` + "\n"
	jAssistant = `{"seq":2,"t":"2026-09-28T00:00:01.000Z","kind":"assistant","text":"hello"}` + "\n"
	jEnded     = `{"seq":3,"t":"2026-09-28T00:00:02.000Z","kind":"status","text":"run ended exit=0"}` + "\n"
)

func newRunLogServer(f *fakeBoxes) *AgentSkillServer {
	s := &AgentSkillServer{execScript: f.exec, runLogPoll: time.Millisecond}
	now := time.Now()
	s.runIndex.add("run-skill", "hello-agent", now, time.Hour)
	s.crewRunMembers = func(_ context.Context, id string) ([]string, bool, error) {
		if id == "run-crew" {
			return []string{"planner", "writer", "reviewer"}, true, nil
		}
		return nil, false, nil
	}
	return s
}

func TestTailRunLog(t *testing.T) {
	full := jStarted + jAssistant + jEnded
	skillPath := journalFile("run-skill", "hello-agent")
	cases := []struct {
		name       string
		files      map[string]string // box:path -> content
		onRead     func(n int, f *fakeBoxes)
		req        *pb.TailRunLogRequest
		wantCode   codes.Code
		wantChunk  string
		wantEnd    int64
		wantTrunc  bool
		wantEnded  bool
		wantSkills []string
		noExec     bool
	}{
		{
			name:      "offset 0 reads the whole small file and sees the end",
			files:     map[string]string{memberBox("hello-agent") + ":" + skillPath: full},
			req:       &pb.TailRunLogRequest{RunId: "run-skill"},
			wantChunk: full, wantEnd: int64(len(full)), wantEnded: true, wantSkills: []string{"hello-agent"},
		},
		{
			name:      "mid-file resumes at the offset",
			files:     map[string]string{memberBox("hello-agent") + ":" + skillPath: full},
			req:       &pb.TailRunLogRequest{RunId: "run-skill", StartOffset: int64(len(jStarted))},
			wantChunk: jAssistant + jEnded, wantEnd: int64(len(full)), wantEnded: true, wantSkills: []string{"hello-agent"},
		},
		{
			name:    "past EOF returns nothing and keeps the offset",
			files:   map[string]string{memberBox("hello-agent") + ":" + skillPath: jStarted},
			req:     &pb.TailRunLogRequest{RunId: "run-skill", StartOffset: 10_000},
			wantEnd: 10_000, wantSkills: []string{"hello-agent"},
		},
		{
			name:      "max_bytes truncates and withholds ended",
			files:     map[string]string{memberBox("hello-agent") + ":" + skillPath: full},
			req:       &pb.TailRunLogRequest{RunId: "run-skill", MaxBytes: 10},
			wantChunk: full[:10], wantEnd: 10, wantTrunc: true, wantSkills: []string{"hello-agent"},
		},
		{
			name:      "not ended while the last line is not run ended",
			files:     map[string]string{memberBox("hello-agent") + ":" + skillPath: jStarted + jAssistant},
			req:       &pb.TailRunLogRequest{RunId: "run-skill"},
			wantChunk: jStarted + jAssistant, wantEnd: int64(len(jStarted + jAssistant)), wantSkills: []string{"hello-agent"},
		},
		{
			name:  "follow returns early once the journal grows",
			files: map[string]string{memberBox("hello-agent") + ":" + skillPath: jStarted},
			onRead: func(n int, f *fakeBoxes) {
				if n == 2 {
					f.put(memberBox("hello-agent"), skillPath, jStarted+jAssistant)
				}
			},
			req:       &pb.TailRunLogRequest{RunId: "run-skill", StartOffset: int64(len(jStarted)), FollowSeconds: 10},
			wantChunk: jAssistant, wantEnd: int64(len(jStarted + jAssistant)), wantSkills: []string{"hello-agent"},
		},
		{
			name:     "unknown run",
			req:      &pb.TailRunLogRequest{RunId: "nope"},
			wantCode: codes.NotFound, noExec: true,
		},
		{
			name:     "skill not a member",
			req:      &pb.TailRunLogRequest{RunId: "run-crew", SkillId: "hello-agent"},
			wantCode: codes.InvalidArgument, noExec: true,
		},
		{
			name: "crew: entry skill by default, skill_ids lists members with a journal",
			files: map[string]string{
				memberBox("planner") + ":" + journalFile("run-crew", "planner"):   jStarted,
				memberBox("reviewer") + ":" + journalFile("run-crew", "reviewer"): full,
			},
			req:       &pb.TailRunLogRequest{RunId: "run-crew"},
			wantChunk: jStarted, wantEnd: int64(len(jStarted)), wantSkills: []string{"planner", "reviewer"},
		},
		{
			name: "crew: named member",
			files: map[string]string{
				memberBox("reviewer") + ":" + journalFile("run-crew", "reviewer"): full,
			},
			req:       &pb.TailRunLogRequest{RunId: "run-crew", SkillId: "reviewer"},
			wantChunk: full, wantEnd: int64(len(full)), wantEnded: true, wantSkills: []string{"reviewer"},
		},
		{name: "bad run_id shape", req: &pb.TailRunLogRequest{RunId: "../etc"}, wantCode: codes.InvalidArgument, noExec: true},
		{name: "dot-dot run_id", req: &pb.TailRunLogRequest{RunId: ".."}, wantCode: codes.InvalidArgument, noExec: true},
		{name: "empty run_id", req: &pb.TailRunLogRequest{}, wantCode: codes.InvalidArgument, noExec: true},
		{name: "bad skill_id shape", req: &pb.TailRunLogRequest{RunId: "run-skill", SkillId: "a/b"}, wantCode: codes.InvalidArgument, noExec: true},
		{name: "negative offset", req: &pb.TailRunLogRequest{RunId: "run-skill", StartOffset: -1}, wantCode: codes.InvalidArgument, noExec: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeBoxes{onRead: tc.onRead}
			for k, v := range tc.files {
				box, path, _ := strings.Cut(k, ":")
				f.put(box, path, v)
			}
			s := newRunLogServer(f)
			resp, err := s.TailRunLog(adminCtx(), tc.req)
			if tc.noExec && f.calls != 0 {
				t.Errorf("ran %d box execs; want none before validation passes", f.calls)
			}
			if tc.wantCode != codes.OK {
				if status.Code(err) != tc.wantCode {
					t.Fatalf("err = %v, want %v", err, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("TailRunLog: %v", err)
			}
			if string(resp.Chunk) != tc.wantChunk || resp.EndOffset != tc.wantEnd || resp.Truncated != tc.wantTrunc || resp.Ended != tc.wantEnded {
				t.Errorf("got chunk=%q end=%d trunc=%v ended=%v; want chunk=%q end=%d trunc=%v ended=%v",
					resp.Chunk, resp.EndOffset, resp.Truncated, resp.Ended, tc.wantChunk, tc.wantEnd, tc.wantTrunc, tc.wantEnded)
			}
			if strings.Join(resp.SkillIds, ",") != strings.Join(tc.wantSkills, ",") {
				t.Errorf("skill_ids = %v, want %v", resp.SkillIds, tc.wantSkills)
			}
		})
	}
}

func TestTailRunLog_FollowGivesUpAtDeadline(t *testing.T) {
	f := &fakeBoxes{}
	f.put(memberBox("hello-agent"), journalFile("run-skill", "hello-agent"), jStarted)
	s := newRunLogServer(f)
	s.runLogPoll = 200 * time.Millisecond
	start := time.Now()
	resp, err := s.TailRunLog(adminCtx(), &pb.TailRunLogRequest{RunId: "run-skill", StartOffset: int64(len(jStarted)), FollowSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Chunk) != 0 || resp.Ended {
		t.Errorf("got %+v, want an empty, not-ended window", resp)
	}
	if el := time.Since(start); el < 500*time.Millisecond || el > 3*time.Second {
		t.Errorf("follow took %v, want about 1s", el)
	}
}

func TestTailRunLog_RunBoundTokenReadsOnlyItsRun(t *testing.T) {
	f := &fakeBoxes{}
	f.put(memberBox("hello-agent"), journalFile("run-skill", "hello-agent"), jStarted)
	s := newRunLogServer(f)
	other := runClaimCtx("agent-hello-agent", "run-other")
	if _, err := s.TailRunLog(other, &pb.TailRunLogRequest{RunId: "run-skill"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	own := runClaimCtx("agent-hello-agent", "run-skill")
	if _, err := s.TailRunLog(own, &pb.TailRunLogRequest{RunId: "run-skill"}); err != nil {
		t.Fatalf("own run: %v", err)
	}
}

func runClaimCtx(user, runID string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		auth.MDKeyUsername, user, auth.MDKeyRoles, "user", auth.MDKeyRunID, runID))
}

func TestTaskRunID_ClaimEnforcement(t *testing.T) {
	operator := adminCtx()
	cases := []struct {
		name      string
		ctx       context.Context
		requested string
		want      string
		wantCode  codes.Code
	}{
		{name: "matching claim passes", ctx: runClaimCtx("agent-a", "run-1"), requested: "run-1", want: "run-1"},
		{name: "absent run_id is stamped with the claim", ctx: runClaimCtx("agent-a", "run-1"), requested: "", want: "run-1"},
		{name: "differing claim is refused", ctx: runClaimCtx("agent-a", "run-1"), requested: "run-2", wantCode: codes.PermissionDenied},
		{name: "operator without a claim keeps its run_id", ctx: operator, requested: "run-2", want: "run-2"},
		{name: "operator without a claim and no run_id", ctx: operator, requested: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := taskRunID(tc.ctx, tc.requested)
			if status.Code(err) != tc.wantCode {
				t.Fatalf("err = %v, want %v", err, tc.wantCode)
			}
			if got != tc.want {
				t.Errorf("run id = %q, want %q", got, tc.want)
			}
		})
	}
}

// SendAgentTask refuses a differing claim before it resolves or dials a peer.
func TestSendAgentTask_RefusesForeignRunID(t *testing.T) {
	s := &AgentSkillServer{}
	_, err := s.SendAgentTask(runClaimCtx("agent-a", "run-1"), &pb.SendAgentTaskRequest{ToPeerId: "b", RunId: "run-2"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
}

func TestRunJournalReaper(t *testing.T) {
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	window := 7 * 24 * time.Hour
	dirs := []runDir{
		{name: "old-run", mtime: now.Add(-8 * 24 * time.Hour)},
		{name: "new-run", mtime: now.Add(-1 * time.Hour)},
		{name: "edge-run", mtime: now.Add(-window)},
		{name: "..", mtime: now.Add(-30 * 24 * time.Hour)},
	}
	if got := staleRunDirs(dirs, now, window); strings.Join(got, ",") != "old-run" {
		t.Errorf("staleRunDirs = %v, want [old-run]", got)
	}

	listing := fmt.Sprintf("%d old-run\n%d new-run\ngarbage\n", now.Add(-8*24*time.Hour).Unix(), now.Add(-time.Hour).Unix())
	var removeScripts []string
	s := &AgentSkillServer{execScript: func(box, script string) (string, error) {
		switch {
		case script == runJournalListScript && box == "agent-a-container":
			return listing, nil
		case script == runJournalListScript:
			return "", nil // missing root: the script exits 0 with no output
		case strings.HasPrefix(script, "rm -rf -- "):
			removeScripts = append(removeScripts, box+" "+script)
			return "", nil
		}
		return "", fmt.Errorf("unexpected %q", script)
	}}
	removed := s.reapRunJournals([]string{"agent-a-container", "agent-empty-container"}, now)
	if want := "agent-a-container:" + runJournalRoot + "/old-run"; strings.Join(removed, ",") != want {
		t.Errorf("removed = %v, want [%s]", removed, want)
	}
	if want := "agent-a-container rm -rf -- '" + runJournalRoot + "/old-run'"; strings.Join(removeScripts, "|") != want {
		t.Errorf("remove scripts = %v, want %q", removeScripts, want)
	}
}

// The read script itself, run by a real sh against a real file: the header,
// the byte range, and the last-line "run ended" test.
func TestJournalReadScript_RealShell(t *testing.T) {
	path := t.TempDir() + "/s.jsonl"
	full := jStarted + jAssistant + jEnded
	if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	sh := func(_, script string) (string, error) {
		out, err := osexec.Command("sh", "-c", script).Output()
		return string(out), err
	}
	w, err := readJournalWindow(sh, "box", path, int64(len(jStarted)), 5)
	if err != nil {
		t.Fatal(err)
	}
	if !w.exists || w.size != int64(len(full)) || !w.lastEnded || string(w.raw) != jAssistant[:5] {
		t.Errorf("window = %+v", w)
	}
	if err := os.WriteFile(path, []byte(jStarted+jAssistant), 0o600); err != nil {
		t.Fatal(err)
	}
	if w, _ = readJournalWindow(sh, "box", path, 0, 1<<20); w.lastEnded || string(w.raw) != jStarted+jAssistant {
		t.Errorf("window = %+v", w)
	}
	if w, _ = readJournalWindow(sh, "box", path+".missing", 0, 10); w.exists {
		t.Errorf("missing file reported as existing")
	}
}
