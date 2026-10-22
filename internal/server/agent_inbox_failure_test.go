package server

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/agentengine"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeInBox is the inBoxRunner seam: the in-box agent-runtime exec and the
// artifact.json read, scripted per test.
type fakeInBox struct {
	stdout, stderr string
	exitCode       int
	execErr        error
	artifact       []byte // nil = artifact.json absent
	readErr        error
	reads          int
}

func (f *fakeInBox) ExecWithExitCode(_ string, _ []string) (string, string, int, error) {
	return f.stdout, f.stderr, f.exitCode, f.execErr
}

func (f *fakeInBox) ReadFile(_, _ string) ([]byte, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	if f.artifact == nil {
		return nil, errors.New("not found")
	}
	return f.artifact, nil
}

func runInBoxWith(t *testing.T, box *fakeInBox) (string, error) {
	t.Helper()
	s, skill := newSkillBoxHarness(t, newFakeRevocationStore())
	s.inBoxOps = box
	return s.runInBoxAgentResult("agent-box", "/seed", "run-1", skill.Id, agentengine.Resolved{}, "")
}

// TestRunInBoxAgentResult_NonZeroExit covers the in-box failure paths: the
// engine's own error recorded in artifact.json must reach the caller, a
// missing runtime is told apart from a failed run, and a failed run with no
// artifact is still an error.
func TestRunInBoxAgentResult_NonZeroExit(t *testing.T) {
	tests := []struct {
		name         string
		box          *fakeInBox
		wantContains []string
		wantMissing  bool // errors.Is(err, errInBoxRuntimeMissing)
	}{
		{
			name: "exit 1 surfaces the artifact error",
			box: &fakeInBox{exitCode: 1, stderr: "agent-runtime: claude run failed",
				artifact: []byte(`{"outputJson":"","error":"upstream 401: API key not valid"}`)},
			wantContains: []string{"upstream 401: API key not valid", "exited 1"},
		},
		{
			name:         "exit 1 with no artifact still errors",
			box:          &fakeInBox{exitCode: 1},
			wantContains: []string{"exited 1"},
		},
		{
			name:         "exit 1 with an unparseable artifact still errors",
			box:          &fakeInBox{exitCode: 1, artifact: []byte("not json")},
			wantContains: []string{"exited 1"},
		},
		{
			name:         "exit 2 (missing run/skill id) surfaces the artifact error",
			box:          &fakeInBox{exitCode: 2, artifact: []byte(`{"error":"CONTAINARIUM_RUN_ID is not set"}`)},
			wantContains: []string{"CONTAINARIUM_RUN_ID is not set", "exited 2"},
		},
		{
			name:         "exit 127 means the runtime is missing",
			box:          &fakeInBox{exitCode: 127, stderr: "bash: agent-runtime: command not found"},
			wantContains: []string{"agent-runtime"},
			wantMissing:  true,
		},
		{
			name:         "exec transport failure errors",
			box:          &fakeInBox{execErr: errors.New("websocket closed")},
			wantContains: []string{"websocket closed"},
		},
		{
			name:         "exit 0 but artifact error is still an error",
			box:          &fakeInBox{artifact: []byte(`{"error":"engine said no"}`)},
			wantContains: []string{"engine said no"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runInBoxWith(t, tc.box)
			if err == nil {
				t.Fatalf("want an error, got success with artifact %q", out)
			}
			for _, w := range tc.wantContains {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error = %q, want it to contain %q", err, w)
				}
			}
			if got := errors.Is(err, errInBoxRuntimeMissing); got != tc.wantMissing {
				t.Errorf("errors.Is(err, errInBoxRuntimeMissing) = %v, want %v (err %q)", got, tc.wantMissing, err)
			}
		})
	}
}

func TestRunInBoxAgentResult_Success(t *testing.T) {
	out, err := runInBoxWith(t, &fakeInBox{artifact: []byte(`{"outputJson":"{\"ok\":true}"}`)})
	if err != nil {
		t.Fatalf("runInBoxAgentResult: %v", err)
	}
	if out != `{"ok":true}` {
		t.Errorf("artifact = %q", out)
	}
}

// TestRunInBoxAgentResult_ArtifactErrorIsScrubbedAndBounded: the engine's
// error is untrusted text from inside the box — it can echo a credential.
// It is redacted before it is returned and capped at 1 KiB.
func TestRunInBoxAgentResult_ArtifactErrorIsScrubbedAndBounded(t *testing.T) {
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJydW4tMSJ9.c2lnbmF0dXJlLXZhbHVl"
	const providerKey = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	msg := "401 for Bearer " + jwt + " key " + providerKey + " api_key=hunter22hunter " + strings.Repeat("é", 4096)
	art := []byte(`{"error":` + jsonQuote(t, msg) + `}`)

	_, err := runInBoxWith(t, &fakeInBox{exitCode: 1, artifact: art})
	if err == nil {
		t.Fatal("want an error")
	}
	got := err.Error()
	for _, secret := range []string{jwt, providerKey, "hunter22hunter"} {
		if strings.Contains(got, secret) {
			t.Errorf("error leaks %q: %q", secret, got)
		}
	}
	if !strings.Contains(got, "401 for") {
		t.Errorf("error lost the non-secret text: %q", got)
	}
	if !utf8.ValidString(got) {
		t.Errorf("error is not valid UTF-8 after truncation")
	}
	if n := len(got); n > maxInBoxErrorBytes+256 {
		t.Errorf("error is %d bytes, want the artifact part capped at %d", n, maxInBoxErrorBytes)
	}
}

// TestRunAgentSkill_FailedInBoxRunIsNotSuccess: a run whose in-box agent
// failed must come back as a gRPC error carrying the engine's reason, never
// as OK with an empty artifact.
func TestRunAgentSkill_FailedInBoxRunIsNotSuccess(t *testing.T) {
	tests := []struct {
		name     string
		box      *fakeInBox
		wantCode codes.Code
		wantText string
	}{
		{
			name: "engine failure",
			box: &fakeInBox{exitCode: 1,
				artifact: []byte(`{"error":"upstream 401: API key not valid"}`)},
			wantCode: codes.Internal,
			wantText: "upstream 401: API key not valid",
		},
		{
			name:     "runtime missing",
			box:      &fakeInBox{exitCode: 127},
			wantCode: codes.FailedPrecondition,
			wantText: "agent-runtime",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, skill := newSkillBoxHarness(t, newFakeRevocationStore())
			s.boxOps = &fakeAgentBox{}
			s.inBoxOps = tc.box

			resp, err := s.RunAgentSkill(ctxAs("admin", true), &pb.RunAgentSkillRequest{SkillId: skill.Id, RunId: "run-fails"})
			if err == nil {
				t.Fatalf("a failed in-box run returned success: %+v", resp)
			}
			if status.Code(err) != tc.wantCode {
				t.Errorf("code = %v, want %v (%v)", status.Code(err), tc.wantCode, err)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantText)
			}
			if !strings.Contains(err.Error(), "run-fails") {
				t.Errorf("error = %q, want it to name the run id", err)
			}
		})
	}
}

func TestRunAgentSkill_SuccessfulInBoxRunReturnsArtifact(t *testing.T) {
	s, skill := newSkillBoxHarness(t, newFakeRevocationStore())
	s.boxOps = &fakeAgentBox{}
	s.inBoxOps = &fakeInBox{artifact: []byte(`{"outputJson":"{\"ok\":true}"}`)}

	resp, err := s.RunAgentSkill(ctxAs("admin", true), &pb.RunAgentSkillRequest{SkillId: skill.Id, RunId: "run-ok"})
	if err != nil {
		t.Fatalf("RunAgentSkill: %v", err)
	}
	if resp.GetArtifactJson() != `{"ok":true}` || resp.GetRunId() != "run-ok" {
		t.Errorf("resp = %+v", resp)
	}
}

func jsonQuote(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
