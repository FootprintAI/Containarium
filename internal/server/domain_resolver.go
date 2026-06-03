package server

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
)

// ipResolver is the slice of *net.Resolver the DomainResolver needs, so it can
// be faked in tests. *net.Resolver satisfies it.
type ipResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DomainResolver maintains a cache of egress_domains → current IPv4 addresses
// (#315 Phase C). The enforcer refreshes it on a loop and folds the cached IPs
// into each tenant's egress allow-list as /32 entries, so an allow-rule like
// "api.github.com" tracks the domain's moving IPs. IPv4-only — the BPF program
// is IPv4-only.
type DomainResolver struct {
	resolver ipResolver
	mu       sync.RWMutex
	cache    map[string][]netip.Addr
}

// NewDomainResolver builds a resolver. A nil ipResolver uses net.DefaultResolver.
func NewDomainResolver(r ipResolver) *DomainResolver {
	if r == nil {
		r = net.DefaultResolver
	}
	return &DomainResolver{resolver: r, cache: make(map[string][]netip.Addr)}
}

// Refresh re-resolves every domain in the set and updates the cache, then prunes
// domains no longer requested. A lookup failure keeps the domain's prior cached
// IPs rather than dropping them — a transient DNS blip must not silently open
// (drop the allow entries → would-deny in enforce) or thrash the allow-list.
func (d *DomainResolver) Refresh(ctx context.Context, domains []string) {
	requested := make(map[string]bool, len(domains))
	for _, dom := range domains {
		if dom == "" || requested[dom] {
			continue
		}
		requested[dom] = true
		addrs, err := d.resolver.LookupNetIP(ctx, "ip4", dom)
		if err != nil {
			continue // keep prior cache for this domain
		}
		v4 := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			if a.Is4() {
				v4 = append(v4, a.Unmap())
			}
		}
		sort.Slice(v4, func(i, j int) bool { return v4[i].Less(v4[j]) })
		d.mu.Lock()
		d.cache[dom] = v4
		d.mu.Unlock()
	}
	// Prune domains no longer in any policy. A failed-lookup domain is still in
	// `requested`, so it's retained (with its prior IPs), not pruned.
	d.mu.Lock()
	for dom := range d.cache {
		if !requested[dom] {
			delete(d.cache, dom)
		}
	}
	d.mu.Unlock()
}

// IPs returns the cached IPv4 addresses for a domain (a copy; empty if unknown).
func (d *DomainResolver) IPs(domain string) []netip.Addr {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append([]netip.Addr(nil), d.cache[domain]...)
}
