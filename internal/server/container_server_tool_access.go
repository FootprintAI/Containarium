package server

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/toolaccess"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SetContainerToolAccess records the tool-access level for platform-started
// (unattended) agent runs on a container (#2944). It only records the level on
// the Incus container config (user.containarium.tool_access), so it survives a
// daemon restart with no separate store and is read back on list/get; applying
// it to the run path is a separate change. UNSPECIFIED removes the key (back to
// "none recorded"). Like the other per-container RPCs, req.Name carries the
// bare username and the handler resolves <username>-container via boxes().Get.
func (s *ContainerServer) SetContainerToolAccess(ctx context.Context, req *pb.SetContainerToolAccessRequest) (*pb.SetContainerToolAccessResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	value, set := toolaccess.ConfigValue(req.ToolAccess)
	if !set && req.ToolAccess != pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED {
		return nil, status.Errorf(codes.InvalidArgument, "unknown tool_access %d", req.ToolAccess)
	}

	username := req.Name
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
		return nil, status.Errorf(codes.InvalidArgument, "container %s is a core container; tool access is for user containers only", info.Ref.Name)
	}
	containerName := info.Ref.Name

	if set {
		if err := s.manager.SetConfig(containerName, incus.ToolAccessKey, value); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to set %s: %v", incus.ToolAccessKey, err)
		}
		log.Printf("[tool-access] container=%q level=%s", containerName, value)
		s.ensureRunUser(containerName, info.State == pb.ContainerState_CONTAINER_STATE_RUNNING)
		return &pb.SetContainerToolAccessResponse{ToolAccess: req.ToolAccess}, nil
	}

	// Clear: remove the key so readers see "absent" rather than an empty string.
	// UnsetConfig is idempotent.
	if err := s.manager.UnsetConfig(containerName, incus.ToolAccessKey); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to clear %s: %v", incus.ToolAccessKey, err)
	}
	log.Printf("[tool-access] container=%q level cleared", containerName)
	return &pb.SetContainerToolAccessResponse{ToolAccess: pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED}, nil
}

// ensureRunUser provisions the run user (ctn-run) as soon as a level is
// recorded, so the box is "up, not signed in" before any run instead of the
// first run creating it and being refused (#3798). provisionBoxRunUser is
// idempotent. Best effort: the level is already recorded, so a failure (box
// stopped, exec error) is logged and the first platform run retries it as
// before. Clearing a level never removes the user.
func (s *ContainerServer) ensureRunUser(containerName string, running bool) {
	if !running {
		return
	}
	rootExec := func(box, script string) (string, error) {
		out, stderr, code, err := s.manager.ExecWithExitCode(box, []string{"bash", "-c", script})
		if err != nil {
			return "", err
		}
		if code != 0 {
			return "", fmt.Errorf("exit %d: %s", code, strings.TrimSpace(stderr))
		}
		return out, nil
	}
	if _, err := provisionBoxRunUser(rootExec, containerName); err != nil {
		log.Printf("[tool-access] container=%q could not provision the run user (the first run retries): %v", containerName, err)
	}
}
