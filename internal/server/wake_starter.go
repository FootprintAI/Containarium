package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

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
	cs            *ContainerServer
	readyTimeoutS int32 // seconds; mirrored into the request
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
	started := time.Now()
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
		log.Printf("[wake] post-start container.Get(%q): %v", username, ierr)
	}

	// Port is the route's TargetPort — we don't have it here, but
	// the wake proxy falls back to route.TargetPort when the
	// starter doesn't report one.
	// StartContainer's readiness probe can be skipped when a Box was
	// already running. An HTTP wake must still wait for the authorized
	// route's TCP port on the live Box IP before proxying the request.
	// Both probes share the original wake timeout; they must not use a
	// stale route IP as evidence that the application is listening.
	if ready && s.cs.routeStore != nil {
		routes, rerr := s.cs.routeStore.ListByContainer(ctx, username+"-container")
		if rerr != nil {
			log.Printf("[wake] route read after start %q: %v", username, rerr)
			return false, ip, 0, nil
		}
		if len(routes) != 0 && routes[0].TargetPort > 0 {
			remaining := time.Duration(s.readyTimeoutS)*time.Second - time.Since(started)
			if remaining <= 0 {
				return false, ip, routes[0].TargetPort, nil
			}
			ip, ready = awaitWakeEndpoint(ctx, remaining, routes[0].TargetPort, func() string {
				info, err := s.cs.GetManager().Get(username)
				if err != nil || info == nil {
					return ""
				}
				return info.IPAddress
			})
			return ready, ip, routes[0].TargetPort, nil
		}
	}
	return ready, ip, 0, nil
}

// awaitWakeEndpoint only returns ready when the live Box's own current IP
// accepts TCP on the already-authorized route port. No route Host or client
// address is trusted for the readiness check. A lack of IP, a timeout or a
// cancelled wake is NOT a successful warmup.
func awaitWakeEndpoint(ctx context.Context, budget time.Duration, port int, readIP func() string) (string, bool) {
	return awaitWakeEndpointWithDial(ctx, budget, port, readIP, func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	})
}

// awaitWakeEndpointWithDial allows tests to hold an in-flight TCP probe
// until cancellation. Production always uses net.Dialer.DialContext.
func awaitWakeEndpointWithDial(ctx context.Context, budget time.Duration, port int, readIP func() string, dial func(context.Context, string) (net.Conn, error)) (string, bool) {
	if budget <= 0 || port <= 0 {
		return "", false
	}
	deadline := time.Now().Add(budget)
	for {
		if err := ctx.Err(); err != nil {
			return "", false
		}
		ip := readIP()
		if ip != "" {
			dialTimeout := 200 * time.Millisecond
			if rem := time.Until(deadline); rem < dialTimeout {
				dialTimeout = rem
			}
			if dialTimeout > 0 {
				probeCtx, cancel := context.WithTimeout(ctx, dialTimeout)
				conn, err := dial(probeCtx, net.JoinHostPort(ip, strconv.Itoa(port)))
				cancel()
				if err == nil {
					_ = conn.Close()
					if ctx.Err() == nil {
						return ip, true
					}
					return "", false
				}
			}
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return "", false
		}
		wait := 100 * time.Millisecond
		if remaining < wait {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", false
		case <-timer.C:
		}
	}
}
