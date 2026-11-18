package coderun

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Every run file the CLI and the MCP tools name lives in the box user's own
// directory (#3682), never in the shared root.
func TestRunLogDir_IsPerUser(t *testing.T) {
	if RunLogRoot != "/tmp/agent-box" {
		t.Errorf("RunLogRoot = %q, want /tmp/agent-box", RunLogRoot)
	}
	for _, tc := range []struct{ got, want string }{
		{RunLogDir("alice"), "/tmp/agent-box/alice"},
		{ApprovalJournalPath("alice", "code"), "/tmp/agent-box/alice/code.input.jsonl"},
		{ApprovalAnswersDir("alice", "code"), "/tmp/agent-box/alice/code.answers"},
	} {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
	if RunLogDir("alice") == RunLogDir("bob") {
		t.Error("two box users share one run directory")
	}
}

// A session knows which box user it logged in as, and so which directory its
// runs are in.
func TestSession_BoxUserIsTheLoginUser(t *testing.T) {
	s := &Session{user: "alice"}
	if s.BoxUser() != "alice" || RunLogDir(s.BoxUser()) != "/tmp/agent-box/alice" {
		t.Errorf("BoxUser() = %q", s.BoxUser())
	}
}

// Without a box user there is no run directory to name: Connect refuses before
// it dials anything.
func TestConnect_RefusesAnEmptyBoxUser(t *testing.T) {
	if _, err := Connect(context.Background(), []string{"-o", "BatchMode=yes", "nowhere.invalid"}, ""); err == nil {
		t.Fatal("Connect with no box user succeeded")
	}
}

type pathRecorder struct{ paths []string }

func (r *pathRecorder) Read(_ context.Context, path string, _ int64, _ time.Duration) ([]byte, int64, bool, error) {
	r.paths = append(r.paths, path)
	return nil, 0, false, errors.New("open: no such file or directory")
}

// code status reads the approval journal from the box user's own directory.
func TestApprovalStatus_ReadsTheUsersJournal(t *testing.T) {
	r := &pathRecorder{}
	if _, err := approvalStatus(context.Background(), r, "alice", "code", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(r.paths) == 0 || r.paths[0] != "/tmp/agent-box/alice/code.input.jsonl" {
		t.Errorf("read %v, want /tmp/agent-box/alice/code.input.jsonl", r.paths)
	}
}
