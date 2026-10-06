package cmd

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium agent run` flag -> RunAgentSkillRequest wiring (#2042).

// resetAgentRunFlags zeroes the package-level flag vars so each table case
// starts from the command's defaults rather than the previous case's values.
func resetAgentRunFlags() {
	agentRunBackendID = ""
	agentRunPool = ""
	agentRunInput = ""
	agentRunGitSource = ""
	agentRunGitRef = ""
	agentRunGitCredentialFile = ""
	agentRunTrackerConnection = ""
	agentRunEngine = ""
}

func TestAgentRun_TrackerConnectionFlagRegistered(t *testing.T) {
	f := agentRunCmd.Flags().Lookup("tracker-connection")
	if f == nil {
		t.Fatal("`agent run` has no --tracker-connection flag")
	}
	if f.DefValue != "" {
		t.Errorf("--tracker-connection default = %q, want empty (no binding)", f.DefValue)
	}
}

// agentRunCaptureServer records the RunAgentSkill request the daemon's
// handler receives.
type agentRunCaptureServer struct {
	pb.UnimplementedAgentSkillServiceServer

	mu  sync.Mutex
	got *pb.RunAgentSkillRequest
}

func (s *agentRunCaptureServer) RunAgentSkill(_ context.Context, req *pb.RunAgentSkillRequest) (*pb.RunAgentSkillResponse, error) {
	s.mu.Lock()
	s.got = proto.Clone(req).(*pb.RunAgentSkillRequest)
	s.mu.Unlock()
	return &pb.RunAgentSkillResponse{Container: &pb.Container{Name: req.GetSkillId() + "-box"}}, nil
}

// startAgentRunDaemon serves capture the way the daemon does and points the
// CLI's global connection flags at it: over gRPC on a loopback port
// (--insecure), or over HTTP through the generated grpc-gateway handler
// (--http) with unknown JSON fields rejected, as the daemon's gateway does.
func startAgentRunDaemon(t *testing.T, transport string, capture *agentRunCaptureServer) {
	t.Helper()
	prevServer, prevHTTP, prevToken, prevInsecure := serverAddr, httpMode, authToken, insecure
	t.Cleanup(func() { serverAddr, httpMode, authToken, insecure = prevServer, prevHTTP, prevToken, prevInsecure })

	switch transport {
	case "grpc":
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		srv := grpc.NewServer()
		pb.RegisterAgentSkillServiceServer(srv, capture)
		go func() { _ = srv.Serve(lis) }()
		t.Cleanup(srv.Stop)
		serverAddr, httpMode, authToken, insecure = lis.Addr().String(), false, "", true
	case "http":
		mux := runtime.NewServeMux(runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: false},
		}))
		if err := pb.RegisterAgentSkillServiceHandlerServer(context.Background(), mux, capture); err != nil {
			t.Fatalf("register gateway handler: %v", err)
		}
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		serverAddr, httpMode, authToken, insecure = srv.URL, true, "tok", false
	default:
		t.Fatalf("unknown transport %q", transport)
	}
}

// TestAgentRun_FlagsReachDaemonRequest runs `agent run` against a daemon
// stand-in over both transports and checks every flag lands in its own
// request field. RunAgentSkill takes its values positionally, so this is the
// test that catches two arguments passed in the wrong order.
func TestAgentRun_FlagsReachDaemonRequest(t *testing.T) {
	credFile := filepath.Join(t.TempDir(), "cred")
	if err := os.WriteFile(credFile, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
		want *pb.RunAgentSkillRequest
	}{
		{
			name: "no flags",
			want: &pb.RunAgentSkillRequest{SkillId: "hello-agent"},
		},
		{
			name: "tracker connection",
			args: []string{"--tracker-connection", "conn-a"},
			want: &pb.RunAgentSkillRequest{SkillId: "hello-agent", TrackerConnection: "conn-a"},
		},
		{
			// #2228: --engine must parse through agentengine.Parse and land on
			// the request's own `engine` field, not be dropped or mapped to
			// the wrong field.
			name: "engine override",
			args: []string{"--engine", "codex"},
			want: &pb.RunAgentSkillRequest{SkillId: "hello-agent", Engine: pb.AgentEngine_AGENT_ENGINE_CODEX},
		},
		{
			// Distinct value per flag, so any two swapped arguments show up.
			name: "every flag",
			args: []string{
				"--backend-id", "local", "--pool", "p1", "--input", `{"q":"hi"}`,
				"--git-source", "https://example.test/repo.git", "--git-ref", "main",
				"--git-credential-file", credFile, "--tracker-connection", "conn-a",
				"--engine", "codex",
			},
			want: &pb.RunAgentSkillRequest{
				SkillId:           "hello-agent",
				BackendId:         "local",
				Pool:              "p1",
				InputJson:         `{"q":"hi"}`,
				GitSource:         "https://example.test/repo.git",
				GitRef:            "main",
				GitCredential:     "tok",
				TrackerConnection: "conn-a",
				Engine:            pb.AgentEngine_AGENT_ENGINE_CODEX,
			},
		},
	}
	for _, transport := range []string{"grpc", "http"} {
		for _, tt := range tests {
			t.Run(transport+"/"+tt.name, func(t *testing.T) {
				capture := &agentRunCaptureServer{}
				startAgentRunDaemon(t, transport, capture)
				resetAgentRunFlags()
				t.Cleanup(resetAgentRunFlags)

				if err := agentRunCmd.ParseFlags(tt.args); err != nil {
					t.Fatalf("parse flags: %v", err)
				}
				if err := runAgentRun(agentRunCmd, []string{"hello-agent"}); err != nil {
					t.Fatalf("runAgentRun: %v", err)
				}
				capture.mu.Lock()
				got := capture.got
				capture.mu.Unlock()
				if !proto.Equal(got, tt.want) {
					t.Errorf("daemon received a different request\n got: %v\nwant: %v", got, tt.want)
				}
			})
		}
	}
}

// TestAgentRun_InvalidEngineFlag_ListsValidNames pins #2228's AC: an unknown
// --engine value is an error listing the valid names (agentengine.Parse's own
// contract), caught before any RPC — never silently sent to the daemon as
// AGENT_ENGINE_UNSPECIFIED.
func TestAgentRun_InvalidEngineFlag_ListsValidNames(t *testing.T) {
	resetAgentRunFlags()
	t.Cleanup(resetAgentRunFlags)
	if err := agentRunCmd.ParseFlags([]string{"--engine", "clawed"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	_, err := resolveAgentRunEngine()
	if err == nil {
		t.Fatal("resolveAgentRunEngine: want an error for an unknown engine name")
	}
	for _, name := range []string{"claude", "codex", "gemini"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not list valid engine name %q", err, name)
		}
	}
}
