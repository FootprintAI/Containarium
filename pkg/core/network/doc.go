// Package network provides network primitives for Containarium hosts:
// passthrough TCP/UDP routing via iptables, port-forwarding setup, and
// PostgreSQL-backed persistence of route definitions.
//
// PassthroughRecord is the persistence view (source of truth);
// PassthroughRoute is the runtime/iptables view. See each type's doc
// comment for the projection between them.
package network
