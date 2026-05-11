// Package coresys manages the _containarium-core system container, which
// hosts the daemon's internal services (PostgreSQL, Redis, Caddy,
// VictoriaMetrics). It is *not* a generic infrastructure abstraction —
// the contained services and their layout are specific to the Containarium
// daemon. A self-hosted user gets one core container per host.
package coresys
