package sentinel

import (
	"strings"
	"sync"
	"time"
)

// PrimaryTTL is the maximum age of a Primary registration before it's considered
// stale and may be evicted. Primaries are expected to heartbeat every PrimaryTTL/3.
const PrimaryTTL = 90 * time.Second

// Primary represents a registered primary daemon serving one pool.
type Primary struct {
	Pool     Pool     `json:"pool"`
	Hostname string   `json:"hostname"`          // primary's own subdomain (e.g. prod.example.com)
	Aliases  []string `json:"aliases,omitempty"` // additional hostnames the primary's Caddy routes (e.g. api.example.com, voice.example.com)
	// BaseDomains anchor suffix routing: any inbound SNI of the form
	// "<anything>.<one-of-BaseDomains>" routes to this primary, so
	// containers that get an ad-hoc subdomain via expose_port don't
	// need to be re-registered as aliases. A primary can advertise
	// multiple base domains so one backend can host workloads that
	// publish under different parent domains (e.g. a lab backend
	// serving both *.lab.example.com and *.demo.example.org).
	// Empty (the default) disables suffix matching for this primary
	// — exact Hostname/Aliases still work. See docs/PER-POOL-BASE-DOMAIN.md.
	BaseDomains   []string  `json:"base_domains,omitempty"`
	IP            string    `json:"ip"`   // primary's reachable IP (typically internal VPC IP)
	Port          int       `json:"port"` // HTTPS port on the primary (typically 443)
	BackendID     string    `json:"backend_id,omitempty"`
	RegisteredAt  time.Time `json:"registered_at"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
}

// PrimaryRegistry tracks pool → primary mappings populated by daemon
// self-registration. Entries that don't heartbeat within PrimaryTTL are
// evicted on read.
type PrimaryRegistry struct {
	mu        sync.RWMutex
	primaries map[Pool]*Primary
	now       func() time.Time
}

// NewPrimaryRegistry creates an empty registry.
func NewPrimaryRegistry() *PrimaryRegistry {
	return &PrimaryRegistry{
		primaries: make(map[Pool]*Primary),
		now:       time.Now,
	}
}

// Register inserts or updates a primary. Pool must be non-empty (one primary
// per pool). The RegisteredAt timestamp is preserved on update.
func (r *PrimaryRegistry) Register(p Primary) *Primary {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	if existing, ok := r.primaries[p.Pool]; ok {
		// Update fields that can change, keep original RegisteredAt
		existing.Hostname = p.Hostname
		existing.Aliases = p.Aliases
		existing.BaseDomains = p.BaseDomains
		existing.IP = p.IP
		existing.Port = p.Port
		existing.BackendID = p.BackendID
		existing.LastHeartbeat = now
		return existing
	}

	stored := p
	stored.RegisteredAt = now
	stored.LastHeartbeat = now
	r.primaries[p.Pool] = &stored
	return &stored
}

// Heartbeat refreshes the LastHeartbeat timestamp for a pool. Returns the
// updated primary, or nil if the pool isn't registered.
func (r *PrimaryRegistry) Heartbeat(pool Pool) *Primary {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.primaries[pool]
	if !ok {
		return nil
	}
	p.LastHeartbeat = r.now()
	return p
}

// Unregister removes a primary by pool name. Returns true if it existed.
func (r *PrimaryRegistry) Unregister(pool Pool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.primaries[pool]
	delete(r.primaries, pool)
	return ok
}

// UnregisterByBackendID removes any primary entry whose BackendID matches.
// Used when a tunnel-registered primary disconnects. Returns the number of
// entries removed.
func (r *PrimaryRegistry) UnregisterByBackendID(backendID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	removed := 0
	for pool, p := range r.primaries {
		if p.BackendID == backendID {
			delete(r.primaries, pool)
			removed++
		}
	}
	return removed
}

// isStale returns true if a primary's heartbeat is too old.
//
// Tunnel-backed primaries (BackendID != "") have explicit lifecycle hooks
// — OnTunnelConnect adds them, OnTunnelDisconnect calls
// UnregisterByBackendID. TTL is for HTTP-registered primaries that may
// have died without DELETE'ing themselves. Skipping TTL for tunnel-backed
// entries prevents the registry from forgetting them while their yamux
// session is still alive (which would otherwise happen 90s after handshake
// since nothing refreshes their heartbeat).
func (r *PrimaryRegistry) isStale(p *Primary, now time.Time) bool {
	if p.BackendID != "" {
		return false
	}
	return now.Sub(p.LastHeartbeat) > PrimaryTTL
}

// LookupByPool returns the primary serving the given pool, or nil. Stale
// entries are treated as absent.
func (r *PrimaryRegistry) LookupByPool(pool Pool) *Primary {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.primaries[pool]
	if !ok {
		return nil
	}
	if r.isStale(p, r.now()) {
		return nil
	}
	return p
}

// LookupByHostname returns the primary registered for the given public
// hostname, matching either the Hostname or any of the Aliases. Stale
// entries are skipped. Used by the SNI router.
func (r *PrimaryRegistry) LookupByHostname(hostname string) *Primary {
	r.mu.RLock()
	defer r.mu.RUnlock()
	now := r.now()
	for _, p := range r.primaries {
		if r.isStale(p, now) {
			continue
		}
		if p.Hostname == hostname {
			return p
		}
		for _, a := range p.Aliases {
			if a == hostname {
				return p
			}
		}
	}
	return nil
}

// LookupByBaseDomainSuffix returns the primary whose BaseDomains
// contain the longest proper DNS suffix of hostname (i.e. hostname is
// of the form "<sub>.<one-of-BaseDomains>"). A primary may advertise
// multiple base domains; each is considered independently. The base
// domain itself is NOT a match — only strict sub-hostnames — so a
// primary's BaseDomains can include another primary's Hostname
// without colliding here. Returns nil when no primary qualifies or
// when two primaries tie on suffix length (ambiguity is a
// misconfiguration; fail closed rather than pick one arbitrarily).
// Stale entries are skipped.
//
// Used by the SNI router after LookupByHostname misses, to route
// ad-hoc container subdomains (e.g. blog.example.org) without
// each one being pre-registered as an alias.
func (r *PrimaryRegistry) LookupByBaseDomainSuffix(hostname string) *Primary {
	if hostname == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	now := r.now()

	var best *Primary
	bestLen := 0
	tie := false
	for _, p := range r.primaries {
		if r.isStale(p, now) {
			continue
		}
		for _, bd := range p.BaseDomains {
			if bd == "" {
				continue
			}
			if !strings.HasSuffix(hostname, "."+bd) {
				continue
			}
			switch {
			case len(bd) > bestLen:
				best = p
				bestLen = len(bd)
				tie = false
			case len(bd) == bestLen && best != nil && p != best:
				tie = true
			}
		}
	}
	if tie {
		return nil
	}
	return best
}

// All returns a snapshot of registered primaries. Stale entries are excluded
// and evicted from the underlying map.
func (r *PrimaryRegistry) All() []*Primary {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	out := make([]*Primary, 0, len(r.primaries))
	for pool, p := range r.primaries {
		if r.isStale(p, now) {
			delete(r.primaries, pool)
			continue
		}
		copy := *p
		out = append(out, &copy)
	}
	return out
}
