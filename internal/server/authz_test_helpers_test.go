package server

import (
	"context"

	"github.com/footprintai/containarium/internal/auth"
)

// testCtx returns a context tagged with the daemon-internal admin
// identity so handlers' AuthorizeTenant check passes. Use it in
// tests that exercise non-authz logic. Per-tenant authz coverage
// lives in internal/auth/authz_test.go.
func testCtx() context.Context {
	return auth.ContextWithSystemIdentity(context.Background())
}
