package server

import (
	"context"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SetCodingAgent is how `containarium code install` records the agent it
// installed over SSH, for a control plane that keeps a per-box record. This
// daemon keeps none, so after the usual container-write gates it answers
// Unimplemented, which the CLI reads as "nothing to update". The gates come
// first so a caller learns nothing about a box it may not manage.
func (s *ContainerServer) SetCodingAgent(ctx context.Context, req *pb.SetCodingAgentRequest) (*pb.SetCodingAgentResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.GetCodingAgent() == pb.CodingAgent_CODING_AGENT_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "coding_agent must name an installed agent")
	}
	if err := auth.AuthorizeTenant(ctx, req.GetUsername()); err != nil {
		return nil, err
	}
	return nil, status.Error(codes.Unimplemented, "this server keeps no per-box coding-agent record")
}
