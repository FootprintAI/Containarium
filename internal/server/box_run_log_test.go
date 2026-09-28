package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/logframe"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// shBox is the fake container manager for the box-run reader (#2123): it
// runs each script with the local sh, the way `incus exec <box> sh -c` would
// run it in the box, against a temp dir standing in for /tmp/agent-box.
type shBox struct {
	mu    sync.Mutex
	boxes []string
	// onExec runs before the n-th exec (0-based), so a test can append to a
	// log between follow polls.
	onExec func(n int)
}

func (b *shBox) exec(box, script string) (string, error) {
	b.mu.Lock()
	n := len(b.boxes)
	b.boxes = append(b.boxes, box)
	hook := b.onExec
	b.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	out, err := osexec.Command("sh", "-c", script).Output()
	if err != nil {
		if ee, ok := err.(*osexec.ExitError); ok {
			return "", fmt.Errorf("%v: %s", err, ee.Stderr)
		}
		return "", err
	}
	return string(out), nil
}

func (b *shBox) calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.boxes)
}

// boxRunServer is a ContainerServer wired only for the box-run reader, with
// bob as the one collaborator on alice's box.
func boxRunServer(t *testing.T, b *shBox) (*ContainerServer, string) {
	t.Helper()
	dir := t.TempDir()
	s := &ContainerServer{
		boxRunExec:   b.exec,
		boxRunLogDir: dir,
		boxRunPoll:   time.Millisecond,
		boxRunCollaborator: func(owner, subject string) (bool, error) {
			return owner == "alice" && subject == "bob", nil
		},
	}
	return s, dir
}

func hostBootID(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Skip("no /proc boot id on this platform")
	}
	return strings.TrimSpace(string(data))
}

type recordSpec struct {
	name     string
	pid      int
	boot     string
	started  time.Time
	exitCode *int
	framed   bool
}

func writeRecord(t *testing.T, dir string, r recordSpec) {
	t.Helper()
	rec := map[string]any{
		"version": 2, "name": r.name, "pid": r.pid, "boot_id": r.boot,
		"command": "claude -p hi", "cwd": "/home/alice",
		"capture_mode": "combined", "log_path": filepath.Join(dir, r.name+".log"),
		"started_at": r.started,
	}
	if r.framed {
		rec["capture_mode"] = "framed"
	}
	if r.exitCode != nil {
		rec["exit_code"] = *r.exitCode
		rec["finished_at"] = r.started.Add(time.Minute)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, r.name+".json"), string(data))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func frames(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		stream, payload, _ := strings.Cut(p, ":")
		b.Write(logframe.EncodeFrame(logframe.Stream(stream[0]), []byte(payload)))
	}
	return b.String()
}

func exitWith(code int) *int { return &code }

func TestListBoxRuns(t *testing.T) {
	boot := hostBootID(t)
	t0 := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	b := &shBox{}
	s, dir := boxRunServer(t, b)

	writeRecord(t, dir, recordSpec{name: "done", pid: 1 << 22, boot: boot, started: t0, exitCode: exitWith(3)})
	writeRecord(t, dir, recordSpec{name: "live", pid: os.Getpid(), boot: boot, started: t0.Add(2 * time.Hour), framed: true})
	writeRecord(t, dir, recordSpec{name: "rebooted", pid: os.Getpid(), boot: "another-boot", started: t0.Add(time.Hour)})
	writeRecord(t, dir, recordSpec{name: "sidecar", pid: 1 << 22, boot: boot, started: t0.Add(3 * time.Hour)})
	writeFile(t, filepath.Join(dir, "sidecar.exit"), "0 1790000000")
	// Neither a rotated-aside record, a malformed one, nor a future version
	// is a current run.
	writeRecord(t, dir, recordSpec{name: "done.1789990000", pid: 1, boot: boot, started: t0.Add(-time.Hour), exitCode: exitWith(0)})
	writeFile(t, filepath.Join(dir, "broken.json"), "{")
	writeFile(t, filepath.Join(dir, "future.json"), `{"version":99,"name":"future"}`)

	resp, err := s.ListBoxRuns(tenantCtx("alice"), &pb.ListBoxRunsRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("ListBoxRuns: %v", err)
	}
	type row struct {
		name    string
		outcome pb.BoxRunOutcome
		code    string
		ended   bool
		mode    pb.CaptureMode
	}
	var got []row
	for _, r := range resp.Runs {
		code := "-"
		if r.ExitCode != nil {
			code = fmt.Sprint(r.GetExitCode())
		}
		got = append(got, row{r.RunName, r.Outcome, code, r.EndedAt != nil, r.CaptureMode})
		if r.LogPath != filepath.Join(dir, r.RunName+".log") {
			t.Errorf("%s log_path = %q", r.RunName, r.LogPath)
		}
		if r.StartedAt == nil {
			t.Errorf("%s has no started_at", r.RunName)
		}
	}
	want := []row{ // newest first
		{"sidecar", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, "0", true, pb.CaptureMode_CAPTURE_MODE_COMBINED},
		{"live", pb.BoxRunOutcome_BOX_RUN_OUTCOME_RUNNING, "-", false, pb.CaptureMode_CAPTURE_MODE_FRAMED},
		{"rebooted", pb.BoxRunOutcome_BOX_RUN_OUTCOME_UNKNOWN, "-", false, pb.CaptureMode_CAPTURE_MODE_COMBINED},
		{"done", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, "3", true, pb.CaptureMode_CAPTURE_MODE_COMBINED},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("runs =\n%v\nwant\n%v", got, want)
	}
	for _, box := range b.boxes {
		if box != "alice-container" {
			t.Errorf("exec'd in %q, want alice-container", box)
		}
	}
}

func TestListBoxRuns_NoRunsYet(t *testing.T) {
	b := &shBox{}
	s, dir := boxRunServer(t, b)
	s.boxRunLogDir = filepath.Join(dir, "never-created")
	resp, err := s.ListBoxRuns(tenantCtx("alice"), &pb.ListBoxRunsRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("ListBoxRuns: %v", err)
	}
	if len(resp.Runs) != 0 {
		t.Errorf("runs = %v, want none", resp.Runs)
	}
}

func TestTailBoxRunLog(t *testing.T) {
	boot := hostBootID(t)
	t0 := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	const plain = "line one\nline two\nline three\n"
	framed := frames("1:hello ", "2:warn\n", "1:wörld\n")
	cases := []struct {
		name      string
		record    *recordSpec
		log       string
		sidecar   string
		onExec    func(n int, dir string)
		req       *pb.TailBoxRunLogRequest
		wantCode  codes.Code
		wantChunk string
		wantEnd   int64
		wantTrunc bool
		wantEnded bool
		wantErrDr bool
	}{
		{
			name:   "offset 0 reads the whole log; ended from the record's exit code",
			record: &recordSpec{name: "task", exitCode: exitWith(0)}, log: plain,
			req:       &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task"},
			wantChunk: plain, wantEnd: int64(len(plain)), wantEnded: true,
		},
		{
			name:   "ended from the exit sidecar when the record has no code",
			record: &recordSpec{name: "task"}, log: plain, sidecar: "1 1790000000",
			req:       &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task"},
			wantChunk: plain, wantEnd: int64(len(plain)), wantEnded: true,
		},
		{
			name:   "a running run is not ended at end of log",
			record: &recordSpec{name: "task"}, log: plain,
			req:       &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task"},
			wantChunk: plain, wantEnd: int64(len(plain)),
		},
		{
			name:   "mid-file resumes at the offset",
			record: &recordSpec{name: "task", exitCode: exitWith(0)}, log: plain,
			req:       &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task", StartOffset: 9},
			wantChunk: plain[9:], wantEnd: int64(len(plain)), wantEnded: true,
		},
		{
			name:   "past EOF returns nothing and keeps the offset",
			record: &recordSpec{name: "task"}, log: plain,
			req:     &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task", StartOffset: 10_000},
			wantEnd: 10_000,
		},
		{
			name:   "max_bytes truncates and withholds ended",
			record: &recordSpec{name: "task", exitCode: exitWith(0)}, log: plain,
			req:       &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task", MaxBytes: 5},
			wantChunk: plain[:5], wantEnd: 5, wantTrunc: true,
		},
		{
			name:   "no log file yet is an empty window",
			record: &recordSpec{name: "task"},
			req:    &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task"},
		},
		{
			name:   "follow returns once the log grows",
			record: &recordSpec{name: "task"}, log: "a\n",
			onExec: func(n int, dir string) {
				if n == 2 {
					appendFile(t, filepath.Join(dir, "task.log"), "b\n")
				}
			},
			req:       &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task", StartOffset: 2, FollowSeconds: 10},
			wantChunk: "b\n", wantEnd: 4,
		},
		{
			name:   "framed: stdout demuxed, stderr dropped and flagged",
			record: &recordSpec{name: "task", exitCode: exitWith(0), framed: true}, log: framed,
			req:       &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task"},
			wantChunk: "hello wörld\n", wantEnd: int64(len(framed)), wantEnded: true, wantErrDr: true,
		},
		{
			name:   "framed: never splits a frame, and resumes at the next one",
			record: &recordSpec{name: "task", exitCode: exitWith(0), framed: true}, log: framed,
			req:       &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task", MaxBytes: 3},
			wantChunk: "hello ", wantEnd: int64(len(frames("1:hello "))), wantTrunc: true,
		},
		{
			name:   "framed: a partly written trailing frame waits for the next call",
			record: &recordSpec{name: "task", framed: true}, log: frames("1:hello ") + "1 aGk",
			req:       &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task"},
			wantChunk: "hello ", wantEnd: int64(len(frames("1:hello "))),
		},
		{
			name:   "framed: an offset inside a frame is refused",
			record: &recordSpec{name: "task", framed: true}, log: framed,
			req:      &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task", StartOffset: 4},
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "unknown run",
			req:      &pb.TailBoxRunLogRequest{Username: "alice", RunName: "nope"},
			wantCode: codes.NotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &shBox{}
			s, dir := boxRunServer(t, b)
			if tc.onExec != nil {
				b.onExec = func(n int) { tc.onExec(n, dir) }
			}
			if tc.record != nil {
				r := *tc.record
				r.pid, r.boot, r.started = os.Getpid(), boot, t0
				writeRecord(t, dir, r)
			}
			if tc.log != "" {
				writeFile(t, filepath.Join(dir, "task.log"), tc.log)
			}
			if tc.sidecar != "" {
				writeFile(t, filepath.Join(dir, "task.exit"), tc.sidecar)
			}
			resp, err := s.TailBoxRunLog(tenantCtx("alice"), tc.req)
			if tc.wantCode != codes.OK {
				if status.Code(err) != tc.wantCode {
					t.Fatalf("err = %v, want %v", err, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("TailBoxRunLog: %v", err)
			}
			if string(resp.Chunk) != tc.wantChunk || resp.EndOffset != tc.wantEnd || resp.Truncated != tc.wantTrunc ||
				resp.Ended != tc.wantEnded || resp.StderrDropped != tc.wantErrDr {
				t.Errorf("got chunk=%q end=%d trunc=%v ended=%v stderr_dropped=%v; want chunk=%q end=%d trunc=%v ended=%v stderr_dropped=%v",
					resp.Chunk, resp.EndOffset, resp.Truncated, resp.Ended, resp.StderrDropped,
					tc.wantChunk, tc.wantEnd, tc.wantTrunc, tc.wantEnded, tc.wantErrDr)
			}
		})
	}
}

func TestTailBoxRunLog_FollowGivesUpAtDeadline(t *testing.T) {
	boot := hostBootID(t)
	b := &shBox{}
	s, dir := boxRunServer(t, b)
	s.boxRunPoll = 200 * time.Millisecond
	writeRecord(t, dir, recordSpec{name: "task", pid: os.Getpid(), boot: boot, started: time.Now()})
	writeFile(t, filepath.Join(dir, "task.log"), "a\n")
	start := time.Now()
	resp, err := s.TailBoxRunLog(tenantCtx("alice"), &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task", StartOffset: 2, FollowSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Chunk) != 0 || resp.Ended || resp.EndOffset != 2 {
		t.Errorf("got %+v, want an empty, not-ended window at offset 2", resp)
	}
	if el := time.Since(start); el < 500*time.Millisecond || el > 3*time.Second {
		t.Errorf("follow took %v, want about 1s", el)
	}
}

// The reader runs as root inside the box, over files the box's user
// controls: a log or record that is a symlink must not be followed.
func TestTailBoxRunLog_RefusesSymlinks(t *testing.T) {
	boot := hostBootID(t)
	secret := filepath.Join(t.TempDir(), "secret")
	writeFile(t, secret, "root-only\n")

	t.Run("log", func(t *testing.T) {
		b := &shBox{}
		s, dir := boxRunServer(t, b)
		writeRecord(t, dir, recordSpec{name: "task", pid: os.Getpid(), boot: boot, started: time.Now(), exitCode: exitWith(0)})
		if err := os.Symlink(secret, filepath.Join(dir, "task.log")); err != nil {
			t.Fatal(err)
		}
		resp, err := s.TailBoxRunLog(tenantCtx("alice"), &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task"})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("err = %v (resp %v), want FailedPrecondition", err, resp)
		}
	})
	t.Run("record", func(t *testing.T) {
		b := &shBox{}
		s, dir := boxRunServer(t, b)
		elsewhere := t.TempDir()
		writeRecord(t, elsewhere, recordSpec{name: "task", pid: os.Getpid(), boot: boot, started: time.Now(), exitCode: exitWith(0)})
		if err := os.Symlink(filepath.Join(elsewhere, "task.json"), filepath.Join(dir, "task.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.TailBoxRunLog(tenantCtx("alice"), &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task"}); status.Code(err) != codes.NotFound {
			t.Fatalf("err = %v, want NotFound", err)
		}
		resp, err := s.ListBoxRuns(tenantCtx("alice"), &pb.ListBoxRunsRequest{Username: "alice"})
		if err != nil || len(resp.Runs) != 0 {
			t.Fatalf("ListBoxRuns = %v, %v; want no runs", resp, err)
		}
	})
}

// Names become path segments inside the box: they are validated before any
// exec, as are the other request bounds.
func TestBoxRuns_ValidationBeforeExec(t *testing.T) {
	cases := []struct {
		name string
		req  *pb.TailBoxRunLogRequest
	}{
		{"empty run_name", &pb.TailBoxRunLogRequest{Username: "alice"}},
		{"run_name with a slash", &pb.TailBoxRunLogRequest{Username: "alice", RunName: "a/b"}},
		{"run_name traversal", &pb.TailBoxRunLogRequest{Username: "alice", RunName: "../../etc/shadow"}},
		{"dot run_name", &pb.TailBoxRunLogRequest{Username: "alice", RunName: "."}},
		{"dot-dot run_name", &pb.TailBoxRunLogRequest{Username: "alice", RunName: ".."}},
		{"run_name with a quote", &pb.TailBoxRunLogRequest{Username: "alice", RunName: "a'b"}},
		{"empty username", &pb.TailBoxRunLogRequest{RunName: "task"}},
		{"username with a slash", &pb.TailBoxRunLogRequest{Username: "a/b", RunName: "task"}},
		{"negative offset", &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task", StartOffset: -1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &shBox{}
			s, _ := boxRunServer(t, b)
			_, err := s.TailBoxRunLog(adminCtx(), tc.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if b.calls() != 0 {
				t.Errorf("ran %d box execs; want none before validation passes", b.calls())
			}
		})
	}
	t.Run("ListBoxRuns empty username", func(t *testing.T) {
		b := &shBox{}
		s, _ := boxRunServer(t, b)
		if _, err := s.ListBoxRuns(adminCtx(), &pb.ListBoxRunsRequest{}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("err = %v, want InvalidArgument", err)
		}
		if b.calls() != 0 {
			t.Errorf("ran %d box execs; want none", b.calls())
		}
	})
}

// Same access as connecting to the box: ssh:write, and the owner (or an
// admin) or one of the box's collaborators. Anyone else never reaches the box.
func TestBoxRuns_Authz(t *testing.T) {
	boot := hostBootID(t)
	cases := []struct {
		name     string
		ctx      context.Context
		wantCode codes.Code
	}{
		{name: "owner", ctx: tenantCtx("alice")},
		{name: "admin", ctx: adminCtx()},
		{name: "collaborator", ctx: tenantCtx("bob")},
		{name: "collaborator with ssh:write", ctx: scopedCtx("bob", auth.ScopeSSHWrite)},
		{name: "stranger", ctx: tenantCtx("mallory"), wantCode: codes.PermissionDenied},
		{name: "owner without ssh:write", ctx: scopedCtx("alice", auth.ScopeContainersRead), wantCode: codes.PermissionDenied},
		{name: "collaborator without ssh:write", ctx: scopedCtx("bob", auth.ScopeContainersRead), wantCode: codes.PermissionDenied},
		{name: "unauthenticated", ctx: context.Background(), wantCode: codes.Unauthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &shBox{}
			s, dir := boxRunServer(t, b)
			writeRecord(t, dir, recordSpec{name: "task", pid: os.Getpid(), boot: boot, started: time.Now(), exitCode: exitWith(0)})
			writeFile(t, filepath.Join(dir, "task.log"), "hi\n")

			_, listErr := s.ListBoxRuns(tc.ctx, &pb.ListBoxRunsRequest{Username: "alice"})
			_, tailErr := s.TailBoxRunLog(tc.ctx, &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task"})
			for rpc, err := range map[string]error{"ListBoxRuns": listErr, "TailBoxRunLog": tailErr} {
				if status.Code(err) != tc.wantCode {
					t.Errorf("%s err = %v, want %v", rpc, err, tc.wantCode)
				}
			}
			if tc.wantCode != codes.OK && b.calls() != 0 {
				t.Errorf("ran %d box execs for a refused caller; want none", b.calls())
			}
		})
	}
}
