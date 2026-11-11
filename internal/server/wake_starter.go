package server

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/footprintai/containarium/pkg/core/box"
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

// wakeTargetPortKey is an internal context hint for the triggering HTTP
// route. Other StartContainer callers retain the generic first-route probe.
type wakeTargetPortKey struct{}

// WakeForRequest starts the Box and probes only the authorized triggering
// route. Already-running Boxes need the explicit probe because their
// StartContainer fast path intentionally skips generic readiness.
func (s *WakeStarter) WakeForRequest(ctx context.Context, username string, targetPort int) (bool, string, int, error) {
	if s == nil || s.cs == nil {
		return false, "", 0, fmt.Errorf("wake starter not configured")
	}
	if targetPort <= 0 {
		return false, "", 0, nil
	}
	started := time.Now()
	startCtx := context.WithValue(ctx, wakeTargetPortKey{}, targetPort)
	resp, err := s.cs.StartContainer(startCtx, &pb.StartContainerRequest{
		Username:            username,
		WaitForReady:        true,
		ReadyTimeoutSeconds: s.readyTimeoutS,
	})
	if err != nil {
		return false, "", targetPort, fmt.Errorf("start: %w", err)
	}
	if resp == nil || resp.ReadyTimedOut {
		return false, "", targetPort, nil
	}

	remaining := time.Duration(s.readyTimeoutS)*time.Second - time.Since(started)
	if remaining <= 0 {
		return false, "", targetPort, nil
	}
	readIP := func() string {
		info, err := s.cs.boxes().Get(ctx, box.BoxRef{Tenant: username})
		if err != nil || info == nil {
			return ""
		}
		return info.IPAddress
	}
	ip, ready := awaitWakeEndpoint(ctx, remaining, targetPort, readIP)
	return ready, ip, targetPort, nil
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
