package cmd

import (
	"context"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium crew run --engine` flag -> RunCrewRequest.engine_overrides
// wiring (#2228), mirroring agent_run_test.go's TestAgentRun_FlagsReachDaemonRequest
// pattern for `agent run --engine`.

func resetCrewRunFlags() {
	crewRunBackendID = ""
	crewRunPool = ""
	crewRunInput = ""
	crewRunGitSource = ""
	crewRunGitRef = ""
	crewRunGitCredentialFile = ""
	crewRunEngineOverrides = nil
}

// crewRunCaptureServer records the RunCrew request the daemon's handler
// receives.
type crewRunCaptureServer struct {
	pb.UnimplementedCrewServiceServer

	mu  sync.Mutex
	got *pb.RunCrewRequest
}

func (s *crewRunCaptureServer) RunCrew(_ context.Context, req *pb.RunCrewRequest) (*pb.RunCrewResponse, error) {
	s.mu.Lock()
	s.got = proto.Clone(req).(*pb.RunCrewRequest)
	s.mu.Unlock()
	return &pb.RunCrewResponse{Run: &pb.CrewRun{Id: "run-1", CrewId: req.GetCrewId()}}, nil
}

func startCrewRunDaemon(t *testing.T, transport string, capture *crewRunCaptureServer) {
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
		pb.RegisterCrewServiceServer(srv, capture)
		go func() { _ = srv.Serve(lis) }()
		t.Cleanup(srv.Stop)
		serverAddr, httpMode, authToken, insecure = lis.Addr().String(), false, "", true
	case "http":
		mux := runtime.NewServeMux(runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: false},
		}))
		if err := pb.RegisterCrewServiceHandlerServer(context.Background(), mux, capture); err != nil {
			t.Fatalf("register gateway handler: %v", err)
		}
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		serverAddr, httpMode, authToken, insecure = srv.URL, true, "tok", false
	default:
		t.Fatalf("unknown transport %q", transport)
	}
}

// TestCrewRun_EngineFlagsReachDaemonRequest proves --engine <skill>=<engine>
// (repeatable) lands in RunCrewRequest.engine_overrides, keyed correctly per
// member, on both transports.
func TestCrewRun_EngineFlagsReachDaemonRequest(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want *pb.RunCrewRequest
	}{
		{
			name: "no override",
			want: &pb.RunCrewRequest{CrewId: "two-engine-crew"},
		},
		{
			name: "one override",
			args: []string{"--engine", "hello-agent-claude=codex"},
			want: &pb.RunCrewRequest{
				CrewId:          "two-engine-crew",
				EngineOverrides: map[string]pb.AgentEngine{"hello-agent-claude": pb.AgentEngine_AGENT_ENGINE_CODEX},
			},
		},
		{
			// Two --engine flags, distinct skill ids and engines, so a mixed-up
			// key or value would show up.
			name: "two overrides",
			args: []string{"--engine", "hello-agent-claude=gemini", "--engine", "hello-agent-codex=claude"},
			want: &pb.RunCrewRequest{
				CrewId: "two-engine-crew",
				EngineOverrides: map[string]pb.AgentEngine{
					"hello-agent-claude": pb.AgentEngine_AGENT_ENGINE_GEMINI,
					"hello-agent-codex":  pb.AgentEngine_AGENT_ENGINE_CLAUDE,
				},
			},
		},
	}
	for _, transport := range []string{"grpc", "http"} {
		for _, tt := range tests {
			t.Run(transport+"/"+tt.name, func(t *testing.T) {
				capture := &crewRunCaptureServer{}
				startCrewRunDaemon(t, transport, capture)
				resetCrewRunFlags()
				t.Cleanup(resetCrewRunFlags)

				if err := crewRunCmd.ParseFlags(tt.args); err != nil {
					t.Fatalf("parse flags: %v", err)
				}
				if err := runCrewRun(crewRunCmd, []string{"two-engine-crew"}); err != nil {
					t.Fatalf("runCrewRun: %v", err)
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

// TestCrewRun_InvalidEngineFlag covers the three ways --engine can be
// malformed: no '=', an unknown engine name (lists the valid ones, same as
// `agent run --engine`), and the same skill_id given twice (a silent
// last-one-wins would let a typo in one flag quietly undo another).
func TestCrewRun_InvalidEngineFlag(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"missing equals", []string{"--engine", "hello-agent-claude"}, "want <skill-id>=<engine>"},
		{"unknown engine name", []string{"--engine", "hello-agent-claude=clawed"}, "unknown agent engine"},
		{"duplicate skill id", []string{"--engine", "hello-agent-claude=claude", "--engine", "hello-agent-claude=codex"}, "given more than once"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetCrewRunFlags()
			t.Cleanup(resetCrewRunFlags)
			if err := crewRunCmd.ParseFlags(tc.args); err != nil {
				t.Fatalf("parse flags: %v", err)
			}
			_, err := resolveCrewRunEngineOverrides()
			if err == nil {
				t.Fatal("resolveCrewRunEngineOverrides: want an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
