package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// RunAgentSkill end to end over both transports (#2042): the values the CLI
// passes must reach the daemon's AgentSkillService handler intact, including
// tracker_connection, whether they travel as gRPC or as JSON through the
// grpc-gateway REST shim.

// fakeAgentSkillServer records the RunAgentSkill request it receives and
// either answers with a fixed response or fails with err.
type fakeAgentSkillServer struct {
	pb.UnimplementedAgentSkillServiceServer

	mu  sync.Mutex
	got *pb.RunAgentSkillRequest
	err error
}

func (f *fakeAgentSkillServer) RunAgentSkill(_ context.Context, req *pb.RunAgentSkillRequest) (*pb.RunAgentSkillResponse, error) {
	f.mu.Lock()
	f.got = proto.Clone(req).(*pb.RunAgentSkillRequest)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return &pb.RunAgentSkillResponse{
		Container:    &pb.Container{Name: req.GetSkillId() + "-box"},
		ArtifactJson: `{"ok":true}`,
		RunId:        "run-1",
	}, nil
}

func (f *fakeAgentSkillServer) received() *pb.RunAgentSkillRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.got
}

// startGRPCAgentServer serves fake on a loopback port and returns a client
// built by the real NewGRPCClient constructor.
func startGRPCAgentServer(t *testing.T, fake *fakeAgentSkillServer) *GRPCClient {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterAgentSkillServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	c, err := NewGRPCClient(lis.Addr().String(), "", true)
	if err != nil {
		t.Fatalf("NewGRPCClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// startGatewayAgentServer serves fake behind the generated grpc-gateway
// handler, with the same JSON options and error body as the daemon's gateway
// (internal/gateway/gateway.go): unknown request fields are rejected, so a
// misspelled key fails here instead of being silently dropped, and errors
// come back as {"error": ..., "code": ...} like customErrorHandler writes.
func startGatewayAgentServer(t *testing.T, fake *fakeAgentSkillServer) *HTTPClient {
	t.Helper()
	mux := runtime.NewServeMux(
		runtime.WithErrorHandler(func(_ context.Context, _ *runtime.ServeMux, _ runtime.Marshaler, w http.ResponseWriter, _ *http.Request, err error) {
			code := runtime.HTTPStatusFromCode(status.Code(err))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "code": code})
		}),
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			MarshalOptions:   protojson.MarshalOptions{EmitUnpopulated: true},
			UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: false},
		}),
	)
	if err := pb.RegisterAgentSkillServiceHandlerServer(context.Background(), mux, fake); err != nil {
		t.Fatalf("register gateway handler: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	return c
}

// agentRunner is the method under test, shared by both clients.
type agentRunner interface {
	RunAgentSkill(skillID, backendID, pool, inputJSON, gitSource, gitRef, gitCredential, trackerConnection string) (*pb.RunAgentSkillResponse, error)
}

// runAgentSkill calls c with req's fields in RunAgentSkill's positional order.
func runAgentSkill(c agentRunner, req *pb.RunAgentSkillRequest) (*pb.RunAgentSkillResponse, error) {
	return c.RunAgentSkill(req.GetSkillId(), req.GetBackendId(), req.GetPool(), req.GetInputJson(),
		req.GetGitSource(), req.GetGitRef(), req.GetGitCredential(), req.GetTrackerConnection())
}

var agentRunTransports = []struct {
	name  string
	start func(*testing.T, *fakeAgentSkillServer) agentRunner
}{
	{"grpc", func(t *testing.T, f *fakeAgentSkillServer) agentRunner { return startGRPCAgentServer(t, f) }},
	{"http", func(t *testing.T, f *fakeAgentSkillServer) agentRunner { return startGatewayAgentServer(t, f) }},
}

func TestRunAgentSkill_RequestReachesServerIntact(t *testing.T) {
	requests := []struct {
		name string
		req  *pb.RunAgentSkillRequest
	}{
		{
			name: "unbound run",
			req:  &pb.RunAgentSkillRequest{SkillId: "hello-agent"},
		},
		{
			name: "tracker connection only",
			req:  &pb.RunAgentSkillRequest{SkillId: "hello-agent", TrackerConnection: "conn-a"},
		},
		{
			name: "every CLI field",
			req: &pb.RunAgentSkillRequest{
				SkillId:           "hello-agent",
				BackendId:         "local",
				Pool:              "p1",
				InputJson:         `{"q":"hi"}`,
				GitSource:         "https://example.test/repo.git",
				GitRef:            "main",
				GitCredential:     "tok",
				TrackerConnection: "conn-a",
			},
		},
	}
	for _, tr := range agentRunTransports {
		for _, rc := range requests {
			t.Run(tr.name+"/"+rc.name, func(t *testing.T) {
				fake := &fakeAgentSkillServer{}
				c := tr.start(t, fake)

				resp, err := runAgentSkill(c, rc.req)
				if err != nil {
					t.Fatalf("RunAgentSkill: %v", err)
				}
				if got := fake.received(); !proto.Equal(got, rc.req) {
					t.Errorf("server received a different request\n got: %v\nwant: %v", got, rc.req)
				}
				if resp.GetContainer().GetName() != "hello-agent-box" || resp.GetRunId() != "run-1" || resp.GetArtifactJson() != `{"ok":true}` {
					t.Errorf("response not decoded: %v", resp)
				}
			})
		}
	}
}

// The daemon rejects a connection the caller doesn't own with
// InvalidArgument (validateTrackerConnection). The CLI does no validation of
// its own, so that rejection must come back to the user on both transports.
func TestRunAgentSkill_SurfacesServerRejection(t *testing.T) {
	const msg = `tracker_connection "nope" not found for tenant "alice"`
	for _, tr := range agentRunTransports {
		t.Run(tr.name, func(t *testing.T) {
			fake := &fakeAgentSkillServer{err: status.Error(codes.InvalidArgument, msg)}
			c := tr.start(t, fake)

			_, err := runAgentSkill(c, &pb.RunAgentSkillRequest{SkillId: "hello-agent", TrackerConnection: "nope"})
			if err == nil {
				t.Fatal("RunAgentSkill succeeded, want the server's rejection")
			}
			if !strings.Contains(err.Error(), msg) {
				t.Errorf("error %q does not carry the server's message %q", err, msg)
			}
			if got := fake.received().GetTrackerConnection(); got != "nope" {
				t.Errorf("server saw tracker_connection %q, want %q", got, "nope")
			}
		})
	}
}
