package server

import "sort"

// Capacity-aware pool placement ranking (#1029 direction 2).
//
// Today resolvePoolPlacement takes the first healthy peer in a pool, in
// nondeterministic Go-map order — so a new container lands on an effectively
// arbitrary backend, and nothing stops several creates in a row from piling
// onto the same host while its neighbours sit idle. #1055's admission gate
// refuses an over-committed host; this spreads load *before* the gate has to.
//
// When enabled (EnableCapacityRanking), the discovery loop caches each peer's
// CPU overcommit ratio (committed cores / logical CPUs) and placement prefers
// the least-committed peer. This is peer-only: the "local backend wins when
// healthy" short-circuit in resolvePoolPlacement is deliberately left unchanged
// (letting local participate in the ranking is a larger behavior change — data
// gravity, latency — best decided on its own).

// leastCommitted returns the candidate that should take the next placement,
// ranked by CPU commitment. Ordering, most-preferred first:
//
//  1. peers with KNOWN capacity, lowest overcommit ratio first;
//  2. peers with UNKNOWN capacity (not yet probed, or last probe failed) —
//     after every known peer, because a host we know is idle is a safer bet
//     than one we can't see. "Unknown" is transient: the discovery loop fills
//     it within one tick of a peer appearing.
//
// Ties (equal ratio, or two unknowns) break by ID so the choice is
// deterministic rather than map-order-arbitrary. Returns nil for no candidates.
// Callers must hold the owning PeerPool's read lock: commitRatio reads fields
// the discovery loop writes under the write lock.
func leastCommitted(candidates []*PeerClient) *PeerClient {
	if len(candidates) == 0 {
		return nil
	}
	ranked := make([]*PeerClient, len(candidates))
	copy(ranked, candidates)
	sort.SliceStable(ranked, func(i, j int) bool {
		ri, iknown := ranked[i].commitRatio()
		rj, jknown := ranked[j].commitRatio()
		if iknown != jknown {
			return iknown // known sorts before unknown
		}
		if iknown && ri != rj {
			return ri < rj // lower commitment first
		}
		return ranked[i].ID < ranked[j].ID // deterministic tie-break
	})
	return ranked[0]
}

// PickLeastCommittedInPool returns the healthy peer in the pool with the lowest
// CPU commitment (see leastCommitted), or nil if the pool has no healthy peer.
// Reads capacity fields under the pool read lock. Falls back to plain
// first-healthy semantics for any peer whose capacity isn't known yet.
func (p *PeerPool) PickLeastCommittedInPool(pool string) *PeerClient {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var candidates []*PeerClient
	for _, pc := range p.peers {
		if pc.Pool == pool && pc.Healthy {
			candidates = append(candidates, pc)
		}
	}
	return leastCommitted(candidates)
}
