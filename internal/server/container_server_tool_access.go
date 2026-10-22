package server

import (
	"context"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Stored spellings of each tool-access level in the
// user.containarium.tool_access_level Incus config key (#2944). An absent key
// is NONE, so a box that predates the feature keeps today's behaviour.
const (
	toolAccessStoredNone       = "none"
	toolAccessStoredBuildTools = "build_tools"
	toolAccessStoredFullSudo   = "full_sudo"
)

// toolAccessFromStored maps the stored string to the proto enum. Anything
// empty or unrecognised reads as NONE: a corrupted or newer-than-this-daemon
// value must never widen what an unattended run may do.
func toolAccessFromStored(v string) pb.ToolAccessLevel {
	switch v {
	case toolAccessStoredBuildTools:
		return pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_BUILD_TOOLS
	case toolAccessStoredFullSudo:
		return pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO
	default:
		return pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_NONE
	}
}

// toolAccessToStored is the inverse of toolAccessFromStored for the levels a
// caller may set. ok is false for UNSPECIFIED and out-of-range values.
func toolAccessToStored(l pb.ToolAccessLevel) (stored string, ok bool) {
	switch l {
	case pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_NONE:
		return toolAccessStoredNone, true
	case pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_BUILD_TOOLS:
		return toolAccessStoredBuildTools, true
	case pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO:
		return toolAccessStoredFullSudo, true
	default:
		return "", false
	}
}

// userBoxForToolAccess resolves the tenant's user box, refusing core
// containers: they are platform services, not workloads an agent runs on.
func (s *ContainerServer) userBoxForToolAccess(ctx context.Context, username string) (*box.BoxStatus, error) {
	if username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, username); err != nil {
		return nil, err
	}
	info, err := s.boxes().Get(ctx, box.BoxRef{Tenant: username})
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "container for user %s not found: %v", username, err)
	}
	if info == nil {
		return nil, status.Errorf(codes.NotFound, "container for user %s not found", username)
	}
	if info.IsCore {
		return nil, status.Errorf(codes.InvalidArgument, "container %s is a core container; tool-access levels are for user containers only", info.Ref.Name)
	}
	return info, nil
}

// GetToolAccessLevel reports the tool-access level recorded for a box.
func (s *ContainerServer) GetToolAccessLevel(ctx context.Context, req *pb.GetToolAccessLevelRequest) (*pb.GetToolAccessLevelResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersRead); err != nil {
		return nil, err
	}
	info, err := s.userBoxForToolAccess(ctx, req.Username)
	if err != nil {
		return nil, err
	}
	return &pb.GetToolAccessLevelResponse{Level: toolAccessFromStored(info.ToolAccessLevel)}, nil
}

// SetToolAccessLevel records a box's tool-access level. It stores the level
// only; applying it on the box (agent allow list, sudoers) is separate work,
// so this call changes no runtime behaviour yet. Setting the level the box
// already has writes nothing.
func (s *ContainerServer) SetToolAccessLevel(ctx context.Context, req *pb.SetToolAccessLevelRequest) (*pb.SetToolAccessLevelResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	stored, ok := toolAccessToStored(req.Level)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "level must be one of NONE, BUILD_TOOLS, FULL_SUDO (got %s)", req.Level)
	}
	info, err := s.userBoxForToolAccess(ctx, req.Username)
	if err != nil {
		return nil, err
	}

	// An absent key already means NONE; any other mismatch (including an
	// unrecognised stored value) is rewritten to the canonical spelling.
	if info.ToolAccessLevel == stored || (info.ToolAccessLevel == "" && stored == toolAccessStoredNone) {
		return &pb.SetToolAccessLevelResponse{Message: "tool-access level already " + stored, Level: req.Level}, nil
	}
	if err := s.manager.SetConfig(info.Ref.Name, incus.ToolAccessLevelKey, stored); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to set %s: %v", incus.ToolAccessLevelKey, err)
	}
	return &pb.SetToolAccessLevelResponse{Message: "tool-access level set to " + stored, Level: req.Level}, nil
}
