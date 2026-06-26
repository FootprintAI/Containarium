// Package expose holds the business logic for "make a container port
// reachable on a public hostname." Both the `containarium expose-port`
// CLI subcommand and the platform MCP's `expose_port` tool delegate to
// this package — the CLI is the canonical surface, and the MCP tool is
// a thin wrapper around the same Run() function via a transport-specific
// adapter implementing APIClient.
//
// Adding a new transport (e.g. CLI HTTP mode) is one adapter type with
// two methods. The validation, IP-resolution, and orchestration stay
// here so behavior can never drift between CLI and MCP.
package expose

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// exposeReadyTimeout / exposePollInterval bound how long Run waits for a
// freshly-created box to get its IP before failing. An agent commonly creates
// a box and immediately exposes a port, racing the box's bring-up — it has no
// IP until it's RUNNING. Waiting absorbs that race instead of erroring (the
// same create→ready fix connect got). vars (not consts) so tests can shrink.
var (
	exposeReadyTimeout = 90 * time.Second
	exposePollInterval = 3 * time.Second
)

// APIClient is the minimal transport surface this package needs. The
// CLI implements it against client.GRPCClient; the MCP tool implements
// it against mcp.Client (HTTP). Tests use a fake.
type APIClient interface {
	// LookupContainer finds a container by its identifier (the same
	// "username" used by create_container / get_container) and returns
	// the canonical container name plus its current LAN IP. State is
	// returned for error messages when the IP isn't yet assigned.
	LookupContainer(ctx context.Context, username string) (name, ip, state string, err error)

	// CreateRoute registers a domain → IP:port mapping in the sentinel
	// reverse proxy.
	CreateRoute(ctx context.Context, p AddRouteParams) (*RouteResult, error)
}

// Options is what the caller (CLI or MCP) gathers from its surface.
type Options struct {
	Username      string
	ContainerPort int
	Domain        string
	Description   string
}

// Validate fails fast on bad caller input. Both surfaces should call
// this before doing any network round-trips so error messages are
// transport-agnostic.
func (o Options) Validate() error {
	if o.Username == "" {
		return fmt.Errorf("username is required")
	}
	if o.ContainerPort <= 0 || o.ContainerPort > 65535 {
		return fmt.Errorf("container_port must be in 1..65535 (got %d)", o.ContainerPort)
	}
	if o.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	return nil
}

// AddRouteParams is the shape passed to APIClient.CreateRoute. Mirrors
// the AddRouteRequest proto fields, but kept transport-agnostic so the
// HTTP/JSON and gRPC adapters each marshal in their own way.
type AddRouteParams struct {
	Domain        string
	TargetIP      string
	TargetPort    int32
	ContainerName string
	Description   string
}

// RouteResult is the success response. Empty Message is fine.
type RouteResult struct {
	Domain        string
	ContainerName string
	ContainerIP   string
	Port          int32
	Message       string
}

// Run is the orchestrator. Resolves the container's current IP via
// LookupContainer (we never trust a caller-supplied IP — recreated
// containers shift IPs and a stale value would silently break the
// route), then registers the route via CreateRoute.
func Run(ctx context.Context, c APIClient, opts Options) (*RouteResult, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	name, ip, err := waitForIP(ctx, c, opts.Username)
	if err != nil {
		return nil, err
	}
	res, err := c.CreateRoute(ctx, AddRouteParams{
		Domain:   opts.Domain,
		TargetIP: ip,
		// #nosec G115 -- Options.Validate above bounds ContainerPort to
		// 1..65535, well within int32 range.
		TargetPort:    int32(opts.ContainerPort),
		ContainerName: name,
		Description:   opts.Description,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add route: %w", err)
	}
	return res, nil
}

// waitForIP resolves the container to (name, ip), polling until the box has an
// IP or the deadline passes. A freshly-created box has no IP until it reaches
// RUNNING, and agents routinely create-then-expose in one breath; waiting
// absorbs that race instead of failing. A box in a state that will never yield
// an IP (stopped/error/etc.) fails fast rather than burning the whole window.
func waitForIP(ctx context.Context, c APIClient, username string) (name, ip string, err error) {
	deadline := time.Now().Add(exposeReadyTimeout)
	for {
		var state string
		name, ip, state, err = c.LookupContainer(ctx, username)
		if err != nil {
			return "", "", fmt.Errorf("failed to look up container %q: %w", username, err)
		}
		if ip != "" {
			return name, ip, nil
		}
		if !isComingUp(state) || !time.Now().Before(deadline) {
			return "", "", fmt.Errorf("container %q has no IP address yet (state: %s)", username, state)
		}
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(exposePollInterval):
		}
	}
}

// isComingUp reports whether a container state is a transient bring-up state
// that will plausibly yield an IP shortly. RUNNING is included because there
// is a brief window where a box is running but its IP isn't reported yet.
// Accepts the proto enum identifier and the friendly form.
func isComingUp(state string) bool {
	s := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(state)), "CONTAINER_STATE_")
	switch s {
	case "CREATING", "PROVISIONING", "STARTING", "PENDING", "RUNNING":
		return true
	}
	return false
}
