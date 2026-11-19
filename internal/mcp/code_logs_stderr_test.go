package mcp

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/runlog"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// runLogRPC is a ContainerService that implements only TailBoxRunLog,
// records each request and answers with one fixed window. With echo it
// reports the requested stream, as a daemon with box_run_stderr does;
// without it it reports none, as an older daemon does.
type runLogRPC struct {
	pb.UnimplementedContainerServiceServer
	echo bool
	mu   sync.Mutex
	reqs []*pb.TailBoxRunLogRequest
}

func (s *runLogRPC) TailBoxRunLog(_ context.Context, req *pb.TailBoxRunLogRequest) (*pb.TailBoxRunLogResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, req)
	resp := &pb.TailBoxRunLogResponse{Chunk: []byte("Error: expired\n"), EndOffset: 15, Ended: true}
	if s.echo {
		resp.Stream = req.GetStream()
	}
	return resp, nil
}

// #3757: code_logs with stream=stderr and `code logs --stderr`'s HTTP client
// make the same TailBoxRunLog RPC through the generated REST mapping, and the
// daemon receives stream STDERR.
func TestCodeLogs_StderrToolAndCLIMakeTheSameRPC(t *testing.T) {
	srv := &runLogRPC{echo: true}
	hs := gatewayFor(t, srv)

	out, err := handleCodeLogs(NewClient(hs.URL, "tok"), map[string]interface{}{"box": "alice", "run": "task", "stream": "stderr"})
	require.NoError(t, err)
	assert.Equal(t, "end_offset: 15\nended: true\ntruncated: false\nstderr_dropped: false\n---\nError: expired\n", out)

	cli, err := client.NewHTTPClient(hs.URL, "tok")
	require.NoError(t, err)
	_, err = runlog.BoxWindow(cli, &pb.TailBoxRunLogRequest{Username: "alice", RunName: "task", Stream: pb.BoxRunLogStream_BOX_RUN_LOG_STREAM_STDERR})
	require.NoError(t, err)

	require.Len(t, srv.reqs, 2)
	assert.Equal(t, pb.BoxRunLogStream_BOX_RUN_LOG_STREAM_STDERR, srv.reqs[0].GetStream())
	assert.True(t, proto.Equal(srv.reqs[0], srv.reqs[1]), "tool sent %v, CLI client sent %v", srv.reqs[0], srv.reqs[1])
}

// stream=log, like no stream at all, is a read of the run's log.
func TestCodeLogs_StreamLogIsTheDefault(t *testing.T) {
	srv := &runLogRPC{echo: true}
	hs := gatewayFor(t, srv)
	for _, args := range []map[string]interface{}{
		{"box": "alice", "run": "task"},
		{"box": "alice", "run": "task", "stream": "log"},
	} {
		_, err := handleCodeLogs(NewClient(hs.URL, "tok"), args)
		require.NoError(t, err)
	}
	require.Len(t, srv.reqs, 2)
	for _, r := range srv.reqs {
		assert.Equal(t, pb.BoxRunLogStream_BOX_RUN_LOG_STREAM_UNSPECIFIED, r.GetStream())
	}
}

// An older daemon ignores the stream and serves the run's log: the tool
// refuses that window instead of showing it as stderr.
func TestCodeLogs_StderrOnAnOlderDaemon(t *testing.T) {
	hs := gatewayFor(t, &runLogRPC{})
	out, err := handleCodeLogs(NewClient(hs.URL, "tok"), map[string]interface{}{"box": "alice", "run": "task", "stream": "stderr"})
	require.ErrorIs(t, err, runlog.ErrBoxRunStderrUnsupported)
	assert.Empty(t, out)
}

func TestCodeLogs_RejectsAnUnknownStream(t *testing.T) {
	srv := &runLogRPC{echo: true}
	hs := gatewayFor(t, srv)
	_, err := handleCodeLogs(NewClient(hs.URL, "tok"), map[string]interface{}{"box": "alice", "run": "task", "stream": "stdout"})
	require.Error(t, err)
	assert.Empty(t, srv.reqs, "an unknown stream must not reach the daemon")
}
