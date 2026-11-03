package server

import pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"

// unavailableRunUsage is the usage every run reports until the daemon reads
// it from the engine's result: an explicit UNAVAILABLE, never nil and never
// zero token counts. It returns a fresh message so callers may modify it.
func unavailableRunUsage() *pb.RunUsage {
	return &pb.RunUsage{Status: pb.RunUsageStatus_RUN_USAGE_STATUS_UNAVAILABLE}
}
