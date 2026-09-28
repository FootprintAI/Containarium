package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2125: POST /tasks on a box's in-box A2A server is a daemon-only endpoint.
// The daemon authenticates with the credential it derived for THAT box; the
// box refuses anything else. These tests cover the daemon's half — that it
// sends the right box's credential, that it never sends a task it cannot
// authenticate, and that a peer's refusal is not reported as a network fault.
// The receiving half (401/403 before engine or journal) is
// agent-runtime/src/a2a.test.ts.

const testA2AJWTSecret = "test-jwt-secret-long-enough-for-hmac-sha256-0123456789"

func a2aTestServer(t *testing.T) *AgentSkillServer {
	t.Helper()
	tm, err := auth.NewTokenManager(testA2AJWTSecret, "containarium-test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return &AgentSkillServer{tokens: tm}
}

// Each box gets its own credential, stable across calls (the daemon recomputes
// rather than stores it) — so a box holding its own cannot use it at a peer.
func TestAgentA2ASecret_PerBoxAndStable(t *testing.T) {
	s := a2aTestServer(t)

	hello := s.agentA2ASecret("hello-agent")
	if hello == "" {
		t.Fatal("no credential derived for hello-agent")
	}
	if again := s.agentA2ASecret("hello-agent"); again != hello {
		t.Errorf("credential is not stable: %q then %q", hello, again)
	}
	if relay := s.agentA2ASecret("relay-agent"); relay == hello {
		t.Errorf("relay-agent derives hello-agent's credential %q", hello)
	}
	// A second daemon with a different signing key cannot open this box.
	otherTM, err := auth.NewTokenManager(testA2AJWTSecret+"-rotated", "containarium-test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	other := &AgentSkillServer{tokens: otherTM}
	if got := other.agentA2ASecret("hello-agent"); got == hello {
		t.Error("a daemon with a different signing key derives the same credential")
	}
	// No token manager (a bare test server, or a daemon that failed to build
	// one) derives nothing rather than a predictable constant.
	if got := (&AgentSkillServer{}).agentA2ASecret("hello-agent"); got != "" {
		t.Errorf("credential without a token manager = %q, want empty", got)
	}
}

// The box's serve-mode process is launched holding its own credential — which
// is what makes the in-box check enforceable at all.
func TestServeModeCommand_ExportsA2AToken(t *testing.T) {
	s := a2aTestServer(t)
	want := "CONTAINARIUM_A2A_TOKEN='" + s.agentA2ASecret("hello-agent") + "' "
	got := s.serveModeCommand("/seed/run-9", "hello-agent")
	if !strings.Contains(got, want) {
		t.Errorf("serveModeCommand = %q, want it to export %q", got, want)
	}
	// A peer's credential must never appear in this box's launch.
	if strings.Contains(got, s.agentA2ASecret("relay-agent")) {
		t.Error("serveModeCommand leaked a peer's credential into this box")
	}
	// Without a derivable credential the box is launched with no token at all,
	// so the runtime fails closed instead of reading an empty one as "any".
	bare := (&AgentSkillServer{}).serveModeCommand("/seed/run-9", "hello-agent")
	if strings.Contains(bare, "CONTAINARIUM_A2A_TOKEN") {
		t.Errorf("serveModeCommand without a token manager = %q, want no A2A token export", bare)
	}
}

// The transport presents the peer box's credential as a bearer token, and the
// task body still carries exactly what it did before.
func TestSendA2ATask_SendsBearerToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		task := &pb.AgentTask{}
		if err := protojson.Unmarshal(body, task); err != nil {
			t.Errorf("peer could not decode task: %v", err)
		}
		if task.GetRunId() != "run-9" {
			t.Errorf("run_id = %q, want run-9", task.GetRunId())
		}
		// The credential must not travel inside the task the peer journals.
		if strings.Contains(string(body), "peer-secret") {
			t.Errorf("task body carries the credential: %s", body)
		}
		out, _ := protojson.Marshal(&pb.AgentArtifact{TaskId: task.GetId(), State: pb.AgentTaskState_AGENT_TASK_STATE_COMPLETED})
		_, _ = w.Write(out)
	}))
	defer srv.Close()

	if _, err := sendA2ATask(context.Background(), srv.URL, &pb.AgentTask{Id: "t", RunId: "run-9"}, "peer-secret"); err != nil {
		t.Fatalf("sendA2ATask: %v", err)
	}
	if gotAuth != "Bearer peer-secret" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer peer-secret")
	}
}

// Fail closed, and fail early: with no credential the daemon does not put a
// task on the wire at all.
func TestSendA2ATask_WithoutCredentialSendsNothing(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := sendA2ATask(context.Background(), srv.URL, &pb.AgentTask{Id: "t"}, "")
	if err == nil {
		t.Fatal("expected an error without a credential, got nil")
	}
	if hits != 0 {
		t.Errorf("peer was contacted %d times, want 0", hits)
	}
}

// A peer that refuses the credential is a different failure from a peer that is
// down, and the error says which.
func TestSendA2ATask_PeerRefusalIsDistinguishable(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"a2a: credential is not this box's daemon credential"}`, code)
		}))
		_, err := sendA2ATask(context.Background(), srv.URL, &pb.AgentTask{Id: "t"}, "wrong")
		srv.Close()
		if err == nil {
			t.Fatalf("%d: expected an error, got nil", code)
		}
		if !errors.Is(err, errA2AUnauthorized) {
			t.Errorf("%d: error %v is not recognized as a refused credential", code, err)
		}
	}
	// A 502 is still a plain transport failure, not an authorization one.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()
	_, err := sendA2ATask(context.Background(), srv.URL, &pb.AgentTask{Id: "t"}, "ok")
	if err == nil || errors.Is(err, errA2AUnauthorized) {
		t.Errorf("502 should not be an authorization failure, got %v", err)
	}
}

// SendAgentTask refuses before it resolves or contacts the peer when the daemon
// holds no credential for it — the task is never delivered unauthenticated.
func TestSendAgentTask_RefusesWithoutPeerCredential(t *testing.T) {
	s := &AgentSkillServer{} // no token manager: nothing derivable
	_, err := s.SendAgentTask(adminCtx(), &pb.SendAgentTaskRequest{ToPeerId: "hello-agent"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("err = %v (code %v), want Internal", err, status.Code(err))
	}
	if !strings.Contains(err.Error(), "authenticate") {
		t.Errorf("error should explain it cannot authenticate to the peer, got: %v", err)
	}
}
