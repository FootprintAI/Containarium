package server

import (
	"context"

	"github.com/footprintai/containarium/internal/app"
)

// WakeRouter is the subset of *wake.Router that ContainerServer needs.
// Defined here so the server package depends on wake only through the
// behaviour it cares about (route swap) and not the rest of the wake
// surface (HTTP handler, audit logger). Satisfied by *wake.Router.
type WakeRouter interface {
	SwapToWake(ctx context.Context, containerName string, routes []*app.RouteRecord) error
	SwapToDirect(ctx context.Context, containerName string, routes []*app.RouteRecord) error
}

// SetWakeRouter wires the wake router. Nil is allowed and disables the
// sleep/wake Caddy mutations — the container still stops on auto-
// sleep, it just doesn't get a wake-on-HTTP route.
func (s *ContainerServer) SetWakeRouter(r WakeRouter) {
	s.wakeRouter = r
}
