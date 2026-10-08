package server

import (
	"context"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// ipResolver is the slice of *net.Resolver the stdlib path needs, so it can
// be faked in tests. *net.Resolver satisfies it.
type ipResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ttlUnknown marks an answer whose resolver cannot report record TTLs (the
// stdlib path); such a name is refreshed on the maxDomainRefresh cap.
const ttlUnknown time.Duration = -1

// maxDomainRefresh caps a name's refresh interval: it refreshes on
// min(record TTL, 60s) (#2379, coding-cli-egress-allowlist.md "Domains").
const maxDomainRefresh = 60 * time.Second

// minDomainRefresh floors the interval so a TTL-0 record cannot hot-loop the
// refresh (and the policy-store read that precedes it).
const minDomainRefresh = time.Second

// dnsAnswer is one name's A+AAAA lookup result.
type dnsAnswer struct {
	Addrs []netip.Addr
	TTL   time.Duration // smallest record TTL in the answer, or ttlUnknown
}

// addrTTLResolver resolves a name to both address families plus a TTL.
type addrTTLResolver interface {
	LookupAddrsTTL(ctx context.Context, host string) (dnsAnswer, error)
}

// stdlibTTLResolver adapts an ipResolver (net.Resolver exposes no TTL).
type stdlibTTLResolver struct{ r ipResolver }

func (s stdlibTTLResolver) LookupAddrsTTL(ctx context.Context, host string) (dnsAnswer, error) {
	addrs, err := s.r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return dnsAnswer{}, err
	}
	return dnsAnswer{Addrs: addrs, TTL: ttlUnknown}, nil
}

// domainEntry is one name's cached state.
type domainEntry struct {
	current  []netip.Addr             // last successful answer, sorted
	retained map[netip.Addr]time.Time // rotated-out addresses -> kept until
	interval time.Duration            // min(TTL, 60s), floored
	due      time.Time                // next refresh
}

// DomainResolver maintains a cache of egress_domains → current addresses
// (#315 Phase C, TTL-aware and dual-stack since #2379). Each name refreshes on
// min(record TTL, 60s). When a lookup succeeds with a different set, the
// rotated-out addresses stay for two refresh intervals so a rotation does not
// cut a live connection; when a lookup fails, the previous set is kept.
// Addrs is the dual-stack view; IPs is the IPv4-only view the current
// (IPv4-only) BPF enforcer consumes.
type DomainResolver struct {
	resolver addrTTLResolver
	now      func() time.Time
	mu       sync.RWMutex
	cache    map[string]*domainEntry
}

// NewDomainResolver builds a resolver. A nil ipResolver uses the system's
// TTL-aware DNS path (falling back to net.DefaultResolver); a non-nil one is
// used as-is with TTLs unknown.
func NewDomainResolver(r ipResolver) *DomainResolver {
	if r == nil {
		return newDomainResolver(newSystemTTLResolver(), time.Now)
	}
	return newDomainResolver(stdlibTTLResolver{r: r}, time.Now)
}

func newDomainResolver(r addrTTLResolver, now func() time.Time) *DomainResolver {
	return &DomainResolver{resolver: r, now: now, cache: make(map[string]*domainEntry)}
}

// refreshInterval clamps a record TTL to [minDomainRefresh, maxDomainRefresh].
func refreshInterval(ttl time.Duration) time.Duration {
	switch {
	case ttl == ttlUnknown || ttl > maxDomainRefresh:
		return maxDomainRefresh
	case ttl < minDomainRefresh:
		return minDomainRefresh
	}
	return ttl
}

// Refresh re-resolves every requested domain that is new or due, then prunes
// domains no longer requested. A lookup failure keeps the domain's prior
// addresses rather than dropping them — a transient DNS blip must not silently
// open (drop the allow entries → would-deny in enforce) or thrash the list.
func (d *DomainResolver) Refresh(ctx context.Context, domains []string) {
	requested := make(map[string]bool, len(domains))
	for _, dom := range domains {
		if dom == "" || requested[dom] {
			continue
		}
		requested[dom] = true
		d.mu.RLock()
		e := d.cache[dom]
		d.mu.RUnlock()
		if e != nil && d.now().Before(e.due) {
			continue
		}
		ans, err := d.resolver.LookupAddrsTTL(ctx, dom)
		now := d.now()
		d.mu.Lock()
		switch {
		case err != nil && e != nil:
			e.due = now.Add(e.interval) // keep prior set; retry next interval
		case err == nil:
			d.cache[dom] = updateEntry(e, ans, now)
		}
		d.mu.Unlock()
	}
	// Prune domains no longer in any policy. A failed-lookup domain is still in
	// `requested`, so it's retained (with its prior addresses), not pruned.
	d.mu.Lock()
	for dom := range d.cache {
		if !requested[dom] {
			delete(d.cache, dom)
		}
	}
	d.mu.Unlock()
}

// updateEntry folds a successful answer into a name's entry (nil = new name).
func updateEntry(e *domainEntry, ans dnsAnswer, now time.Time) *domainEntry {
	fresh := normalizeAddrs(ans.Addrs)
	interval := refreshInterval(ans.TTL)
	if e == nil {
		return &domainEntry{current: fresh, retained: map[netip.Addr]time.Time{}, interval: interval, due: now.Add(interval)}
	}
	inFresh := make(map[netip.Addr]bool, len(fresh))
	for _, a := range fresh {
		inFresh[a] = true
		delete(e.retained, a) // current again: no longer an overlap entry
	}
	for _, a := range e.current {
		if !inFresh[a] {
			e.retained[a] = now.Add(2 * interval)
		}
	}
	for a, until := range e.retained {
		if !now.Before(until) {
			delete(e.retained, a)
		}
	}
	e.current, e.interval, e.due = fresh, interval, now.Add(interval)
	return e
}

// normalizeAddrs unmaps, dedupes and sorts (IPv4 before IPv6).
func normalizeAddrs(in []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]bool, len(in))
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		a = a.Unmap()
		if a.IsValid() && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// Addrs returns a domain's addresses, both families: the current set plus any
// rotated-out addresses still inside their overlap window (a copy; empty if
// unknown).
func (d *DomainResolver) Addrs(domain string) []netip.Addr {
	now := d.now()
	d.mu.RLock()
	defer d.mu.RUnlock()
	e := d.cache[domain]
	if e == nil {
		return nil
	}
	out := append([]netip.Addr(nil), e.current...)
	for a, until := range e.retained {
		if now.Before(until) {
			out = append(out, a)
		}
	}
	return normalizeAddrs(out)
}

// IPs returns only the IPv4 addresses from Addrs: the view the IPv4-only BPF
// enforcer folds into its egress map.
func (d *DomainResolver) IPs(domain string) []netip.Addr {
	var v4 []netip.Addr
	for _, a := range d.Addrs(domain) {
		if a.Is4() {
			v4 = append(v4, a)
		}
	}
	return v4
}

// NextRefreshDelay is how long until the earliest cached name is due, clamped
// to [minDomainRefresh, maxDomainRefresh]; maxDomainRefresh when nothing is
// cached, so newly added domains are picked up within the cap.
func (d *DomainResolver) NextRefreshDelay() time.Duration {
	now := d.now()
	d.mu.RLock()
	defer d.mu.RUnlock()
	delay := maxDomainRefresh
	for _, e := range d.cache {
		if w := e.due.Sub(now); w < delay {
			delay = w
		}
	}
	return max(delay, minDomainRefresh)
}
