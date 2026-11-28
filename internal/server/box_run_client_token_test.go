//go:build !containarium_client

package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/agentbox"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// StartBoxRunRequest.client_token (#3668): a caller-chosen identifier, stored
// on the run record and returned on BoxRun, so a caller can tell its own run
// from one a person started by hand under the same name.

// clientTokensByRun lists username's runs and returns each run's client_token.
func clientTokensByRun(t *testing.T, s *ContainerServer, username string) map[string]string {
	t.Helper()
	resp, err := s.ListBoxRuns(tenantCtx(username), &pb.ListBoxRunsRequest{Username: username})
	if err != nil {
		t.Fatalf("ListBoxRuns: %v", err)
	}
	got := map[string]string{}
	for _, r := range resp.GetRuns() {
		got[r.GetRunName()] = r.GetClientToken()
	}
	return got
}

// The token comes back on the started run and on every listing, also from a
// daemon that did not start the run (a restart reads the record in the box);
// a run started without one, or by hand, shows none.
func TestStartBoxRun_ClientTokenIsReturnedAndSurvivesARestart(t *testing.T) {
	boot := hostBootID(t)
	u := newFakeBoxUser(t, 0, 0)
	s, dir, _ := boxRunStartServer(t, u)

	starts := []struct{ name, token string }{
		{"caller-a", "job-42/attempt 1"},
		{"caller-b", "job-43/attempt 1"},
		{"no-token", ""},
	}
	for _, st := range starts {
		resp, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
			Username: "alice", Prompt: "hi", RunName: st.name, ClientToken: st.token,
		})
		if err != nil {
			t.Fatalf("StartBoxRun %s: %v", st.name, err)
		}
		if got := resp.GetRun().GetClientToken(); got != st.token {
			t.Errorf("StartBoxRun %s: run.client_token = %q, want %q", st.name, got, st.token)
		}
		waitForOutcome(t, s, "alice", st.name, pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 10*time.Second)
	}
	// A run started by hand (code run over SSH, through agent-box) has a
	// record with no client_token.
	writeRecord(t, dir, recordSpec{name: "by-hand", pid: 1 << 22, boot: boot, started: time.Now().UTC(), exitCode: exitWith(0)})

	want := map[string]string{"caller-a": "job-42/attempt 1", "caller-b": "job-43/attempt 1", "no-token": "", "by-hand": ""}
	restarted := &ContainerServer{
		boxRunExec:   (&shBox{}).exec,
		boxRunLogDir: dir,
		boxRunPoll:   time.Millisecond,
		boxRunCollaborator: func(owner, subject string) (bool, error) {
			return false, nil
		},
	}
	for label, srv := range map[string]*ContainerServer{"the starting daemon": s, "a restarted daemon": restarted} {
		got := clientTokensByRun(t, srv, "alice")
		for name, token := range want {
			if tok, ok := got[name]; !ok {
				t.Errorf("%s: run %q is not listed", label, name)
			} else if tok != token {
				t.Errorf("%s: run %q client_token = %q, want %q", label, name, tok, token)
			}
		}
	}

	raw, err := os.ReadFile(filepath.Join(dir, "caller-a.json"))
	if err != nil {
		t.Fatalf("read the run record: %v", err)
	}
	rec, err := agentbox.DecodeRunRecord(raw)
	if err != nil {
		t.Fatalf("decode the run record: %v", err)
	}
	if rec.ClientToken != "job-42/attempt 1" {
		t.Errorf("record client_token = %q, want the token as sent", rec.ClientToken)
	}
	raw, err = os.ReadFile(filepath.Join(dir, "no-token.json"))
	if err != nil {
		t.Fatalf("read the run record: %v", err)
	}
	if strings.Contains(string(raw), "client_token") {
		t.Errorf("a run started without a token records one: %s", raw)
	}
}

// Command mode keeps the token the same way an engine run does.
func TestStartBoxRun_CommandMode_KeepsTheClientToken(t *testing.T) {
	u := newFakeBoxUser(t, 0, 0)
	s, _, _ := boxRunStartServer(t, u)

	resp, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Command: "echo ok", RunName: "cmd-1", ClientToken: "deploy 7",
	})
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if got := resp.GetRun().GetClientToken(); got != "deploy 7" {
		t.Errorf("run.client_token = %q, want %q", got, "deploy 7")
	}
	run := waitForOutcome(t, s, "alice", "cmd-1", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 10*time.Second)
	if got := run.GetClientToken(); got != "deploy 7" {
		t.Errorf("ListBoxRuns run.client_token = %q, want %q", got, "deploy 7")
	}
}

func TestValidateBoxRunClientToken(t *testing.T) {
	for _, ok := range []string{"", "job-42", "attempt 1 of 3", "run:7f3c2a@caller", "日本語のトークン", strings.Repeat("a", boxRunClientTokenMaxBytes)} {
		if err := validateBoxRunClientToken(ok); err != nil {
			t.Errorf("validateBoxRunClientToken(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		strings.Repeat("a", boxRunClientTokenMaxBytes+1),
		strings.Repeat("é", boxRunClientTokenMaxBytes/2+1), // 130 bytes, 65 characters
		"line\nbreak", "carriage\rreturn", "tab\there", "nul\x00", "\x1b[31mred", "del\x7f", "c1\u0085control",
		"bad-utf8-\xff",
	} {
		if status.Code(validateBoxRunClientToken(bad)) != codes.InvalidArgument {
			t.Errorf("validateBoxRunClientToken(%q) is not InvalidArgument", bad)
		}
	}
}

// A token the daemon would not store as sent is refused before anything runs
// in the box: no listing, no record.
func TestStartBoxRun_InvalidClientTokenRefusedUpFront(t *testing.T) {
	u := newFakeBoxUser(t, 0, 0)
	s, dir, list := boxRunStartServer(t, u)
	for _, bad := range []string{strings.Repeat("a", boxRunClientTokenMaxBytes+1), "two\nlines", "\x1b[2J"} {
		_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
			Username: "alice", Prompt: "hi", RunName: "bad", ClientToken: bad,
		})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("client_token %q: err = %v, want InvalidArgument", bad, err)
		}
	}
	if n := list.calls(); n != 0 {
		t.Errorf("%d exec(s) in the box before the refusal, want none", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "bad.json")); err == nil {
		t.Error("a run record was written for a refused client_token")
	}
}
