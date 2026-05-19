package server

import (
	"context"
	"fmt"
	"log"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// WakeStarter is the adapter that the wake.WakeProxy uses to start a
// sleeping container in response to an inbound HTTP request. It wraps
// ContainerServer.StartContainer with WaitForReady=true so the wake
// proxy can hold the request until the container's primary port is
// dial-ready.
//
// Lives in the server package (rather than wake) so the wake package
// doesn't have to depend on the gRPC pb types or the full
// ContainerServer surface — it just sees the narrow interface
// `wake.WakeStarter`.
type WakeStarter struct {
	cs             *ContainerServer
	readyTimeoutS  int32 // seconds; mirrored into the request
}

// NewWakeStarter constructs the adapter. readyTimeoutSeconds is the
// upper bound on StartContainer's readiness probe — usually 30s,
// matching wake.WakeProxy's own wait timeout.
func NewWakeStarter(cs *ContainerServer, readyTimeoutSeconds int32) *WakeStarter {
	if readyTimeoutSeconds <= 0 {
		readyTimeoutSeconds = 30
	}
	return &WakeStarter{cs: cs, readyTimeoutS: readyTimeoutSeconds}
}

// WakeForRequest implements wake.WakeStarter. Returns:
//   - ready=true when StartContainer reports the container is up and
//     its primary port is dial-ready.
//   - ready=false (no err) on probe timeout — the wake proxy responds
//     503 Retry-After: 5 in this case.
//   - err on a hard failure of the Start call itself.
//
// containerIP / port are read from the post-Start container info so the
// wake proxy can build a reverse-proxy target. We don't rely on the
// route store here — the route's TargetIP may be stale during a fresh
// start cycle, but `manager.Get` reads the live Incus state.
func (s *WakeStarter) WakeForRequest(ctx context.Context, username string) (bool, string, int, error) {
	if s == nil || s.cs == nil {
		return false, "", 0, fmt.Errorf("wake starter not configured")
	}
	resp, err := s.cs.StartContainer(ctx, &pb.StartContainerRequest{
		Username:            username,
		WaitForReady:        true,
		ReadyTimeoutSeconds: s.readyTimeoutS,
	})
	if err != nil {
		return false, "", 0, fmt.Errorf("start: %w", err)
	}
	ready := resp != nil && !resp.ReadyTimedOut

	// Pull the IP from the live Incus state. The container.Manager
	// is the canonical place — it's what StartContainer queried for
	// the response we already have, but the pb.Container shape
	// doesn't expose IPAddress directly in all proto versions, so
	// we re-fetch.
	var ip string
	if info, ierr := s.cs.GetManager().Get(username); ierr == nil && info != nil {
		ip = info.IPAddress
	} else if ierr != nil {
		log.Printf("[wake] post-start container.Get(%s): %v", username, ierr)
	}

	// Port is the route's TargetPort — we don't have it here, but
	// the wake proxy falls back to route.TargetPort when the
	// starter doesn't report one.
	return ready, ip, 0, nil
}
