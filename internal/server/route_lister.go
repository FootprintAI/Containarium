package server

import (
	"context"

	"github.com/footprintai/containarium/internal/app"
)

// routeLister is the subset of *app.RouteStore that ContainerServer
// touches. Introduced so waitForContainerReady's dial loop can be
// unit-tested with an in-memory fake (no pgx pool, no postgres).
//
// Method set covers exactly the production call sites in this package
// (cascadeContainerCleanup, MoveContainer cutover, waitForContainerReady):
// nothing more. Adding a method here only when a new call site needs it
// keeps the test surface minimal.
type routeLister interface {
	ListByContainer(ctx context.Context, containerName string) ([]*app.RouteRecord, error)
	Delete(ctx context.Context, fullDomain string) error
	Save(ctx context.Context, route *app.RouteRecord) error
}
