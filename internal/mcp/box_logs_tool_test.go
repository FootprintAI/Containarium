package mcp

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/boxlogs"
	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// logsRPC is a ContainerService that implements only TailBoxLogs and
// records each request it receives.
type logsRPC struct {
	pb.UnimplementedContainerServiceServer
	mu   sync.Mutex
	reqs []*pb.TailBoxLogsRequest
	resp *pb.TailBoxLogsResponse
}

func (s *logsRPC) TailBoxLogs(_ context.Context, req *pb.TailBoxLogsRequest) (*pb.TailBoxLogsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, req)
	return s.resp, nil
}

// gatewayFor serves srv behind the generated grpc-gateway REST mapping, the
// way the daemon serves its REST API.
func gatewayFor(t *testing.T, srv pb.ContainerServiceServer) *httptest.Server {
	t.Helper()
	mux := runtime.NewServeMux()
	require.NoError(t, pb.RegisterContainerServiceHandlerServer(context.Background(), mux, srv))
	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)
	return hs
}

var logsWindow = &pb.TailBoxLogsResponse{
	Status: pb.BoxLogsStatus_BOX_LOGS_STATUS_OK, Runtime: pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_DOCKER,
	Cursor: "next", More: true, DroppedFrames: 1,
	Lines: []*pb.BoxLogLine{
		{Time: timestamppb.New(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)), SourceKind: pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_JOURNAL, Source: "nginx.service", Text: "started"},
		{Time: timestamppb.New(time.Date(2026, 11, 11, 12, 0, 1, 0, time.UTC)), SourceKind: pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_CONTAINER, Source: "web", Text: "GET /", Truncated: true},
	},
}

// Criterion 7: the MCP box_logs tool and the CLI's client make the same
// TailBoxLogs RPC, through the generated REST mapping, for the same ask.
func TestBoxLogs_ToolAndCLIMakeTheSameRPC(t *testing.T) {
	srv := &logsRPC{resp: logsWindow}
	hs := gatewayFor(t, srv)
	since := time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC)

	out, err := handleBoxLogs(NewClient(hs.URL, "tok"), map[string]interface{}{
		"box": "alice", "since": since.Format(time.RFC3339), "tail": float64(7),
		"units": []interface{}{"nginx", "cron"}, "containers": []interface{}{"web"},
		"max_lines": float64(50), "follow_seconds": float64(3),
	})
	require.NoError(t, err)

	cli, err := client.NewHTTPClient(hs.URL, "tok")
	require.NoError(t, err)
	_, err = boxlogs.Fetch(cli, &pb.TailBoxLogsRequest{Username: "alice", Since: timestamppb.New(since), Tail: 7,
		Units: []string{"nginx", "cron"}, Containers: []string{"web"}, MaxLines: 50, FollowSeconds: 3})
	require.NoError(t, err)

	require.Len(t, srv.reqs, 2)
	assert.True(t, proto.Equal(srv.reqs[0], srv.reqs[1]), "tool sent %v, CLI client sent %v", srv.reqs[0], srv.reqs[1])
	assert.Equal(t, "alice", srv.reqs[0].GetUsername())
	assert.Equal(t, []string{"nginx", "cron"}, srv.reqs[0].GetUnits())
	assert.True(t, srv.reqs[0].GetSince().AsTime().Equal(since))

	assert.Equal(t, "cursor: next\nmore: true\nruntime: docker\ndropped_frames: 1\n---\n"+
		"2026-11-11T12:00:00Z journal/nginx.service started\n"+
		"2026-11-11T12:00:01Z container/web GET / [truncated]\n", out)
}

// A cursor from a previous call is passed through unchanged.
func TestBoxLogs_ToolPassesCursor(t *testing.T) {
	srv := &logsRPC{resp: logsWindow}
	hs := gatewayFor(t, srv)
	_, err := handleBoxLogs(NewClient(hs.URL, "tok"), map[string]interface{}{"box": "alice", "cursor": "abc-_123"})
	require.NoError(t, err)
	require.Len(t, srv.reqs, 1)
	assert.Equal(t, "abc-_123", srv.reqs[0].GetCursor())
}

func TestBoxLogs_ToolErrors(t *testing.T) {
	_, err := handleBoxLogs(NewClient("http://127.0.0.1:0", "t"), map[string]interface{}{})
	require.Error(t, err)

	_, err = handleBoxLogs(NewClient("http://127.0.0.1:0", "t"), map[string]interface{}{"box": "alice", "since": "yesterday"})
	require.Error(t, err)

	srv := &logsRPC{resp: &pb.TailBoxLogsResponse{Status: pb.BoxLogsStatus_BOX_LOGS_STATUS_BOX_STOPPED, Reason: "the box is not running"}}
	hs := gatewayFor(t, srv)
	_, err = handleBoxLogs(NewClient(hs.URL, "tok"), map[string]interface{}{"box": "alice"})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "stopped"), err.Error())
}

func TestBoxLogs_ToolScope(t *testing.T) {
	assert.Equal(t, auth.ScopeSSHWrite, toolScopeAssignments()["box_logs"])
}
