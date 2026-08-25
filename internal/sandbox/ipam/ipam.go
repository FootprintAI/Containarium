// Package ipam allocates static IPv4 addresses for pool members (#1488
// Phase 3): "Pool members get a statically allocated IP from a per-host
// IPAM range at warm time... The lease wait happens during warm-up, where
// it is free. WaitForNetwork disappears from the claim path entirely
// rather than being made faster."
//
// Pure in-memory bookkeeping — no Incus, no host networking, no live
// container needed to build or test this package. What it hands out is a
// candidate address; actually wiring it onto a NIC (config.NIC.IPv4Address
// on the bridged device, already present in pkg/core/incus) is the pool
// reconciler's job at warm time, not this package's.
package ipam

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// ErrExhausted is returned by Allocate when no address in the range is
// free (accounting for the quarantine window on recently released ones).
var ErrExhausted = errors.New("ipam: address range exhausted")

// ErrNotAllocated is returned by Release for an address this Allocator
// never handed out (or already released).
var ErrNotAllocated = errors.New("ipam: address not currently allocated")

// Allocator hands out unique IPv4 addresses from a fixed inclusive range.
// Safe for concurrent use.
type Allocator struct {
	mu sync.Mutex

	start, end uint32 // inclusive range, host byte order
	quarantine time.Duration

	allocated map[uint32]struct{}  // currently held
	released  map[uint32]time.Time // ip -> release time; still quarantined until +quarantine
	cursor    uint32               // next candidate to scan from (round-robin, spreads reuse across the range)
}

// New builds an Allocator over the inclusive range [startIP, endIP].
// hostIP is the interface address the range's own bridge/gateway already
// occupies (e.g. incusbr0's address) — New refuses a range that contains
// it, since handing that address to a sandbox would collide with the
// host itself. quarantine bounds how long a released address stays
// unavailable for reuse before Allocate will hand it out again; 0 means
// immediate reuse is fine.
//
// A released IP with a live ARP/neighbor-cache entry elsewhere on the
// bridge is a cross-sandbox routing bug waiting to happen — quarantine
// exists to let that cache entry age out before the address is reused by
// someone else.
func New(startIP, endIP, hostIP string, quarantine time.Duration) (*Allocator, error) {
	start, err := parseIPv4(startIP)
	if err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}
	end, err := parseIPv4(endIP)
	if err != nil {
		return nil, fmt.Errorf("end: %w", err)
	}
	if start > end {
		return nil, fmt.Errorf("start %s is after end %s", startIP, endIP)
	}
	host, err := parseIPv4(hostIP)
	if err != nil {
		return nil, fmt.Errorf("host: %w", err)
	}
	if host >= start && host <= end {
		return nil, fmt.Errorf("range %s-%s overlaps the host's own address %s", startIP, endIP, hostIP)
	}
	if quarantine < 0 {
		return nil, fmt.Errorf("quarantine must not be negative, got %s", quarantine)
	}

	return &Allocator{
		start:      start,
		end:        end,
		quarantine: quarantine,
		allocated:  make(map[uint32]struct{}),
		released:   make(map[uint32]time.Time),
		cursor:     start,
	}, nil
}

// Allocate claims and returns the next free address in the range,
// skipping anything currently held or still within its quarantine
// window. Returns ErrExhausted if none qualifies.
func (a *Allocator) Allocate() (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	total := a.end - a.start + 1
	for i := uint32(0); i < total; i++ {
		candidate := a.start + (a.cursor-a.start+i)%total
		if a.isFreeLocked(candidate, now) {
			a.allocated[candidate] = struct{}{}
			delete(a.released, candidate)
			a.cursor = candidate + 1
			return ipFromUint32(candidate), nil
		}
	}
	return nil, ErrExhausted
}

func (a *Allocator) isFreeLocked(ip uint32, now time.Time) bool {
	if _, held := a.allocated[ip]; held {
		return false
	}
	if releasedAt, wasReleased := a.released[ip]; wasReleased {
		if now.Sub(releasedAt) < a.quarantine {
			return false
		}
	}
	return true
}

// Release returns ip to the pool, starting its quarantine window (if
// any) from now. Returns ErrNotAllocated if ip isn't currently held by
// this Allocator.
func (a *Allocator) Release(ip net.IP) error {
	v, err := ipToUint32(ip)
	if err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, held := a.allocated[v]; !held {
		return fmt.Errorf("%w: %s", ErrNotAllocated, ip)
	}
	delete(a.allocated, v)
	a.released[v] = time.Now()
	return nil
}

func parseIPv4(s string) (uint32, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP %q", s)
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, fmt.Errorf("%q is not an IPv4 address", s)
	}
	return binary.BigEndian.Uint32(v4), nil
}

func ipToUint32(ip net.IP) (uint32, error) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, fmt.Errorf("invalid IPv4 address %v", ip)
	}
	return binary.BigEndian.Uint32(v4), nil
}

func ipFromUint32(v uint32) net.IP {
	b := make(net.IP, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}
