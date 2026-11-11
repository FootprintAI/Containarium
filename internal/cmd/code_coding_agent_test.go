package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/coderun/engine"
	"github.com/footprintai/containarium/internal/connectcore"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `code install` installs the agent over SSH, so a control plane that keeps a
// per-box coding-agent record never sees the install. After a verified install
// the CLI records the agent with SetCodingAgent. Recording is best-effort: the
// install has already succeeded, so a server that keeps no record (501/404) or
// a failed call never fails the command.

func TestCodingAgentForEngine(t *testing.T) {
	cases := []struct {
		name   engine.Name
		want   pb.CodingAgent
		wantOK bool
	}{
		{engine.NameClaude, pb.CodingAgent_CODING_AGENT_CLAUDE_CODE, true},
		{engine.NamePi, pb.CodingAgent_CODING_AGENT_UNSPECIFIED, false},
		{engine.NameCodex, pb.CodingAgent_CODING_AGENT_UNSPECIFIED, false},
	}
	for _, c := range cases {
		got, ok := codingAgentForEngine(c.name)
		if got != c.want || ok != c.wantOK {
			t.Errorf("codingAgentForEngine(%q) = %v, %v; want %v, %v", c.name, got, ok, c.want, c.wantOK)
		}
	}
}

func TestConnectAPI_SetCodingAgent(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	var gotBody connectcore.SetCodingAgentRequest
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		_, _ = io.WriteString(w, "{}")
	}))
	t.Cleanup(ts.Close)

	api := &connectAPI{hc: ts.Client(), server: ts.URL, token: "tok"}
	if _, err := api.SetCodingAgent(context.Background(), "alice", pb.CodingAgent_CODING_AGENT_CLAUDE_CODE); err != nil {
		t.Fatalf("SetCodingAgent: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/containers/alice/coding-agent" {
		t.Errorf("request = %s %s; want POST /v1/containers/alice/coding-agent", gotMethod, gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q; want the caller's bearer token", gotAuth)
	}
	if gotBody.CodingAgent != "CODING_AGENT_CLAUDE_CODE" {
		t.Errorf("body codingAgent = %q; want the proto enum name", gotBody.CodingAgent)
	}
}

func TestReportCodingAgentRecord(t *testing.T) {
	cases := []struct {
		name   string
		status int
		err    error
		want   string
	}{
		{"recorded", http.StatusOK, nil, "✓ recorded coding agent"},
		{"server keeps no record (501)", http.StatusNotImplemented, errors.New("status 501"), "keeps no coding-agent record"},
		{"server keeps no record (404)", http.StatusNotFound, errors.New("status 404"), "keeps no coding-agent record"},
		{"call failed", http.StatusInternalServerError, errors.New("status 500"), "could not record the coding agent"},
		{"no response", 0, errors.New("dial tcp: refused"), "could not record the coding agent"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var diag bytes.Buffer
			reportCodingAgentRecord(&diag, "alice", pb.CodingAgent_CODING_AGENT_CLAUDE_CODE, c.status, c.err)
			if !strings.Contains(diag.String(), c.want) {
				t.Errorf("diag = %q; want it to contain %q", diag.String(), c.want)
			}
			if c.err != nil && c.status != http.StatusNotImplemented && c.status != http.StatusNotFound &&
				!strings.Contains(diag.String(), "containarium code install alice") {
				t.Errorf("a failed record must say how to retry; diag = %q", diag.String())
			}
		})
	}
}

func TestCodeInstall_RecordsClaudeCodeAfterAVerifiedInstall(t *testing.T) {
	var recorded []string
	_, _, _, err := runInstallWith(t, "alice", nil, installFakes{
		recordAgent: func(box string, agent pb.CodingAgent) {
			recorded = append(recorded, fmt.Sprintf("%s=%s", box, agent))
		},
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if len(recorded) != 1 || recorded[0] != "alice=CODING_AGENT_CLAUDE_CODE" {
		t.Errorf("recorded = %v; want exactly [alice=CODING_AGENT_CLAUDE_CODE]", recorded)
	}
}

func TestCodeInstall_RecordsNothingWhenVerifyFails(t *testing.T) {
	verify := defaultClaudeEngine().VerifyScript()
	var recorded []string
	_, _, _, err := runInstallWith(t, "alice", nil, installFakes{
		exec: func(script string) (string, error) {
			if script == verify {
				return "", errors.New("claude: command not found")
			}
			return "ok", nil
		},
		recordAgent: func(box string, agent pb.CodingAgent) {
			recorded = append(recorded, box)
		},
	})
	if err == nil {
		t.Fatal("install succeeded with a failing verify")
	}
	if len(recorded) != 0 {
		t.Errorf("recorded %v for an install that did not verify", recorded)
	}
}
