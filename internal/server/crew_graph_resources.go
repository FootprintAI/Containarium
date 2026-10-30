package server

import (
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// validateLocalNodeResources returns the local backend to pin a constrained
// node to. Empty means legacy placement. This checks the last measured host
// profile, not free capacity: normal provisioning/admission still applies.
func (s *CrewServer) validateLocalNodeResources(node *pb.TaskNode, parent *pb.RunCrewRequest) (string, error) {
	r := node.GetResources()
	if r.GetMinCpuCores() == 0 && r.GetMinMemoryBytes() == 0 && !r.GetRequiresGpu() {
		return "", nil
	}
	if s.agents == nil || s.agents.recipes == nil || s.agents.recipes.containers == nil {
		return "", status.Errorf(codes.FailedPrecondition, "node %q: local capability profile is unavailable", node.Id)
	}
	containers := s.agents.recipes.containers
	if containers.peerPool != nil && containers.peerPool.LocalBackendID() == "" {
		return "", status.Errorf(codes.FailedPrecondition, "node %q: local backend identity is unavailable", node.Id)
	}
	local := containers.localBackendID()
	if parent.BackendId != "" && parent.BackendId != local {
		return "", status.Errorf(codes.FailedPrecondition, "node %q: resource requirements support only the local backend", node.Id)
	}
	if parent.Pool != "" && (containers.peerPool == nil || containers.peerPool.LocalPool() != parent.Pool) {
		return "", status.Errorf(codes.FailedPrecondition, "node %q: requested pool does not contain the local backend", node.Id)
	}
	if !containers.localBackendHealthy() {
		return "", status.Errorf(codes.FailedPrecondition, "node %q: local backend is unhealthy", node.Id)
	}
	profile, ok := containers.capabStore().Current()
	if !ok {
		return "", status.Errorf(codes.FailedPrecondition, "node %q: no local capability profile; record one with 'containarium backends profile'", node.Id)
	}
	if profile.CPUCores < r.MinCpuCores {
		return "", status.Errorf(codes.FailedPrecondition, "node %q: local profile does not meet minimum CPU cores (%d)", node.Id, r.MinCpuCores)
	}
	if profile.TotalMemoryBytes < r.MinMemoryBytes {
		return "", status.Errorf(codes.FailedPrecondition, "node %q: local profile does not meet minimum memory bytes (%d)", node.Id, r.MinMemoryBytes)
	}
	if r.RequiresGpu && !profile.GPUAvailable {
		return "", status.Errorf(codes.FailedPrecondition, "node %q: local profile has no validated GPU", node.Id)
	}
	return local, nil
}
