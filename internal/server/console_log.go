package server

import (
	"context"
	"fmt"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// GetConsoleLog returns a VM instance's boot-time console ring-buffer
// log — a static read, not a live attach. Diagnoses boot hangs (BIOS/UEFI
// POST, bootloader, kernel panic pre-network) that leave the instance
// unreachable via SSH or its own tunnel agent, since none of those paths
// require the instance's own network stack to be up.
func (s *ContainerServer) GetConsoleLog(ctx context.Context, req *pb.GetConsoleLogRequest) (*pb.GetConsoleLogResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}
	if s.manager == nil {
		return &pb.GetConsoleLogResponse{}, nil
	}

	log, err := s.manager.GetConsoleLog(req.Username)
	if err != nil {
		// An LXC container has no serial console — Incus errors on the
		// request. That's not a failure worth surfacing to the caller,
		// who just wants to know there's nothing to show.
		return &pb.GetConsoleLogResponse{}, nil
	}
	return &pb.GetConsoleLogResponse{Log: log}, nil
}
