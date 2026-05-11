# pkg/core

Reusable Go packages extracted from the Containarium daemon: container
lifecycle, networking primitives, and storage abstractions.

These packages are imported by the OSS daemon in this repository and are
designed to also support out-of-tree consumers — e.g., third-party tools or
a future hosted Containarium service that drives many daemons.

## Packages

| Package | Purpose |
|---|---|
| `incus` | Wraps the Incus/LXC API. Exposes the `Backend` interface (mockable) and `Client` (production implementation). |
| `incus/incustest` | `MockBackend` — a test double satisfying `incus.Backend`. |
| `container` | Container lifecycle Manager: create, start, stop, delete; SSH/cgroup wiring. |
| `coresys` | Manages the `_containarium-core` system container (PostgreSQL, Redis, Caddy used by the daemon itself). |
| `network` | Bridge configuration, passthrough routing, port-forward primitives. |
| `expose` | Port exposure orchestration (domain → IP:port). |
| `ospkg` | OS package manager abstraction (apt, dnf). |
| `ostype` | OS detection and image resolution. |
| `stacks` | Software stack definitions (nodejs, python, etc.). |

## Stability

**Not yet stable.** Treat this as `v0.x` — interfaces may change without
notice as the daemon's needs evolve and as the API gets exercised by
additional consumers. A `v1.x` line will be cut once the API is validated
by at least two consumers.

## License

Apache 2.0, matching the parent module. These packages contain primitives
any self-hosted user already runs as part of the OSS daemon — nothing is
being moved behind a paywall by this extraction.

## Consumer example

```go
import (
    "github.com/footprintai/containarium/pkg/core/container"
)

// Production: backed by a real Incus client.
m, err := container.New()

// Test: backed by an in-memory mock.
import "github.com/footprintai/containarium/pkg/core/incus/incustest"

mock := incustest.NewMockBackend()
m := container.NewWithBackend(mock)
```

See `incus/incustest/example_test.go` for runnable examples.

## Origin

These packages were extracted from `internal/` in May 2026 so consumers
beyond the OSS daemon could import them. The original `internal/core`
package was renamed to `coresys` during the move to avoid the awkward
`pkg/core/core/` path.

The `incus.Backend` interface and `incustest.MockBackend` test double
landed during the same extraction; they're the supported way to drive
the platform without spinning up a real Incus daemon.
