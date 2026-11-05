package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The OSS daemon keeps no per-box coding-agent record, so SetCodingAgent
// answers Unimplemented, but only after the same gates as any container write:
// a caller learns nothing about a box it may not manage. The server is built
// with nil dependencies, so passing means every answer comes before any of
// them is touched.
func TestSetCodingAgent_GatedThenUnimplemented(t *testing.T) {
	claude := pb.CodingAgent_CODING_AGENT_CLAUDE_CODE
	cases := []struct {
		name string
		req  *pb.SetCodingAgentRequest
		user string
		want codes.Code
	}{
		{name: "own box", req: &pb.SetCodingAgentRequest{Username: "alice", CodingAgent: claude}, user: "alice", want: codes.Unimplemented},
		{name: "another tenant's box", req: &pb.SetCodingAgentRequest{Username: "bob", CodingAgent: claude}, user: "alice", want: codes.PermissionDenied},
		{name: "no username", req: &pb.SetCodingAgentRequest{CodingAgent: claude}, user: "alice", want: codes.InvalidArgument},
		{name: "unspecified agent", req: &pb.SetCodingAgentRequest{Username: "alice"}, user: "alice", want: codes.InvalidArgument},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := (&ContainerServer{}).SetCodingAgent(tenantCtx(c.user), c.req)
			if status.Code(err) != c.want {
				t.Fatalf("got %v (code %v), want %v", err, status.Code(err), c.want)
			}
		})
	}
}

func TestSetCodingAgent_NeedsContainersWrite(t *testing.T) {
	ctx := auth.ContextWithTestSubjectScopes(context.Background(), "alice", []string{"user"}, []string{auth.ScopeContainersRead})
	_, err := (&ContainerServer{}).SetCodingAgent(ctx,
		&pb.SetCodingAgentRequest{Username: "alice", CodingAgent: pb.CodingAgent_CODING_AGENT_CLAUDE_CODE})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v (code %v), want PermissionDenied for a token without containers:write", err, status.Code(err))
	}
}
