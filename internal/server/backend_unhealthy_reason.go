package server

import (
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Why a backend in ListBackends is unhealthy (#3722). A bare healthy=false
// left a client unable to tell a peer that stopped answering from one that was
// never seen, or from a reachable host whose container driver is failing.
//
// Each function takes the exact inputs ListBackends derives BackendInfo.healthy
// from and returns UNSPECIFIED precisely when that verdict is healthy, so
// healthy == (unhealthy_reason == UNSPECIFIED) holds by construction.

// localUnhealthyReason is the reason for the local backend. Its healthy
// verdict is the Incus liveness probe (localBackendHealthy), so an unhealthy
// local backend is a failing container driver.
func localUnhealthyReason(healthy bool) pb.BackendUnhealthyReason {
	if healthy {
		return pb.BackendUnhealthyReason_BACKEND_UNHEALTHY_REASON_UNSPECIFIED
	}
	return pb.BackendUnhealthyReason_BACKEND_UNHEALTHY_REASON_DRIVER_ERROR
}

// peerUnhealthyReason is the reason for a tunnel peer. healthy is the
// sentinel's verdict from discovery and lastSeen is when the peer was last
// reported healthy (PeerClient.LastSeenAt), zero if it never was.
func peerUnhealthyReason(healthy bool, lastSeen time.Time) pb.BackendUnhealthyReason {
	switch {
	case healthy:
		return pb.BackendUnhealthyReason_BACKEND_UNHEALTHY_REASON_UNSPECIFIED
	case lastSeen.IsZero():
		return pb.BackendUnhealthyReason_BACKEND_UNHEALTHY_REASON_NEVER_SEEN
	default:
		return pb.BackendUnhealthyReason_BACKEND_UNHEALTHY_REASON_NO_RECENT_HEARTBEAT
	}
}
