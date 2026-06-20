package server

import (
	"context"
	"log"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SetContainerAttribution merges labels onto an EXISTING container's config
// (cloud #746). The hosted control plane stamps attribution labels
// (cloud_org_id / cloud_container_id / managed_by) at CreateContainer today;
// this lets it stamp them AFTER the fact, which the cloud's adopt flow (cloud
// #539) needs to bring a host's pre-existing (orphan) container under org
// management.
//
// Merge, not replace: each provided label is set via manager.AddLabel (which
// writes incus.LabelPrefix+key), leaving labels not named here intact — so an
// adopt can't clobber a box's monitoring / os-type / other labels. The labels
// live on the Incus config, so they survive daemon restart and are read back on
// list/get the same way create-time labels are. Like the other per-container
// RPCs, req.Name carries the bare username and the manager resolves
// <username>-container.
//
// Cloud→daemon plumbing (like /authorized-keys/sentinel), not a standalone
// operator action — stamping cloud org UUIDs by hand is meaningless, so there's
// no `containarium` CLI verb; the operator surface is the cloud's adopt flow.
func (s *ContainerServer) SetContainerAttribution(ctx context.Context, req *pb.SetContainerAttributionRequest) (*pb.SetContainerAttributionResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if len(req.Labels) == 0 {
		return nil, status.Error(codes.InvalidArgument, "labels must not be empty")
	}
	for k := range req.Labels {
		if k == "" {
			return nil, status.Error(codes.InvalidArgument, "label key must not be empty")
		}
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
		return nil, status.Errorf(codes.InvalidArgument, "container %s is a core container; attribution is for user containers only", info.Ref.Name)
	}

	for k, v := range req.Labels {
		if err := s.manager.AddLabel(username, k, v); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to set label %q: %v", k, err)
		}
	}

	labels, err := s.manager.GetLabels(username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read labels back: %v", err)
	}
	log.Printf("[attribution] container=%s labels+=%d", info.Ref.Name, len(req.Labels))
	return &pb.SetContainerAttributionResponse{Labels: labels}, nil
}
