package netbpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Map / program / section names — must match SEC(".maps") names and the
// program section in experimental/ebpf-phaseA/netpolicy.bpf.c.
const (
	progNetpolicy   = "netpolicy_ingress"
	mapVethPolicy   = "veth_policy"
	mapEgressCIDR   = "egress_cidr"
	mapIPTenant     = "ip_tenant"
	mapStats        = "stats"
	mapEvents       = "events"
	statSeen        = uint32(0)
	statWouldDeny   = uint32(1)
	statsEntryCount = 2
)

// Loader owns a loaded netpolicy BPF collection and the per-veth TCX links it
// has attached. It is the Phase A productionization of cmd/ebpf-phase0: instead
// of a counter it loads the real policy program, populates the policy maps, and
// attaches the program to each managed container's host veth in TC_INGRESS.
//
// Linux-only at runtime: cilium/ebpf compiles on every platform (so the daemon
// builds on a dev mac), but Load/Attach return errors on non-Linux kernels.
type Loader struct {
	coll  *ebpf.Collection
	links map[int]link.Link // ifindex -> TCX link
}

// Load reads the compiled BPF object at objPath, loads the collection, and
// verifies the expected program + maps are present. Build the object with:
//
//	clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu \
//	    -c experimental/ebpf-phaseA/netpolicy.bpf.c -o netpolicy.bpf.o
func Load(objPath string) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("netbpf: RemoveMemlock: %w", err)
	}
	if _, err := os.Stat(objPath); err != nil {
		return nil, fmt.Errorf("netbpf: BPF object %q: %w", objPath, err)
	}
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("netbpf: load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("netbpf: load collection: %w", err)
	}
	for _, name := range []string{mapVethPolicy, mapEgressCIDR, mapIPTenant, mapStats, mapEvents} {
		if coll.Maps[name] == nil {
			coll.Close()
			return nil, fmt.Errorf("netbpf: BPF object missing map %q (rebuild netpolicy.bpf.o?)", name)
		}
	}
	if coll.Programs[progNetpolicy] == nil {
		coll.Close()
		return nil, fmt.Errorf("netbpf: BPF object missing program %q", progNetpolicy)
	}
	return &Loader{coll: coll, links: make(map[int]link.Link)}, nil
}

// AttachVeth attaches the policy program to a container's host veth in
// TC_INGRESS via TCX (kernel ≥ 6.6). Idempotent per ifindex.
func (l *Loader) AttachVeth(ifindex int) error {
	if _, ok := l.links[ifindex]; ok {
		return nil
	}
	lnk, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   l.coll.Programs[progNetpolicy],
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("netbpf: attach TCX ingress on ifindex %d: %w", ifindex, err)
	}
	l.links[ifindex] = lnk
	return nil
}

// DetachVeth removes the program from a veth (e.g. on container stop/delete).
func (l *Loader) DetachVeth(ifindex int) error {
	lnk, ok := l.links[ifindex]
	if !ok {
		return nil
	}
	delete(l.links, ifindex)
	return lnk.Close()
}

// SetVethPolicy writes the per-veth policy config into the veth_policy map,
// keyed by the veth's host ifindex.
func (l *Loader) SetVethPolicy(ifindex int, cfg PolicyConfig) error {
	key := uint32(ifindex) // #nosec G115 -- ifindex is a small positive int
	val := vethPolicyValue(cfg)
	if err := l.coll.Maps[mapVethPolicy].Update(&key, val[:], ebpf.UpdateAny); err != nil {
		return fmt.Errorf("netbpf: update veth_policy[%d]: %w", ifindex, err)
	}
	return nil
}

// AddEgress installs one egress allow-list LPM entry.
func (l *Loader) AddEgress(e EgressEntry) error {
	key := egressKeyBytes(e)
	one := uint8(1)
	if err := l.coll.Maps[mapEgressCIDR].Update(key[:], &one, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("netbpf: update egress_cidr: %w", err)
	}
	return nil
}

// SetIPTenant maps a managed container IP (network byte order, 4 bytes) to its
// tenant ID, so the program can distinguish same-tenant peers from external
// destinations.
func (l *Loader) SetIPTenant(ip [4]byte, tenantID uint32) error {
	key := binary.LittleEndian.Uint32(ip[:]) // raw 4 bytes as the map's __u32 key; kernel compares bytes
	if err := l.coll.Maps[mapIPTenant].Update(&key, &tenantID, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("netbpf: update ip_tenant: %w", err)
	}
	return nil
}

// Stats reads the (seen, wouldDeny) counters — the validator's success signal,
// mirroring the Phase 0 counter read.
func (l *Loader) Stats() (seen, wouldDeny uint64, err error) {
	keySeen, keyDeny := statSeen, statWouldDeny
	if err = l.coll.Maps[mapStats].Lookup(&keySeen, &seen); err != nil {
		return 0, 0, fmt.Errorf("netbpf: read stats[seen]: %w", err)
	}
	if err = l.coll.Maps[mapStats].Lookup(&keyDeny, &wouldDeny); err != nil {
		return 0, 0, fmt.Errorf("netbpf: read stats[wouldDeny]: %w", err)
	}
	return seen, wouldDeny, nil
}

// EventsMap exposes the perf-event array so the denied-flow consumer (a later
// increment) can open a perf reader over it.
func (l *Loader) EventsMap() *ebpf.Map { return l.coll.Maps[mapEvents] }

// Close detaches every veth link and frees the collection.
func (l *Loader) Close() error {
	var errs []error
	for idx, lnk := range l.links {
		if err := lnk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close link ifindex %d: %w", idx, err))
		}
	}
	l.links = nil
	if l.coll != nil {
		l.coll.Close()
		l.coll = nil
	}
	return errors.Join(errs...)
}

// --- byte-layout helpers (kept next to the C struct definitions they mirror) ---

// vethPolicyValue serializes a PolicyConfig into the 8-byte `struct policy_cfg`
// layout: u32 tenant_id, u8 mode, u8 allow_intra, u8 pad[2]. Native byte order
// (the kernel reads the map value with native loads).
func vethPolicyValue(cfg PolicyConfig) [8]byte {
	var b [8]byte
	binary.NativeEndian.PutUint32(b[0:4], cfg.TenantID)
	b[4] = cfg.Mode
	b[5] = cfg.AllowIntra
	return b
}

// egressKeyBytes serializes an EgressEntry into the 12-byte `struct egress_key`
// layout: u32 prefixlen, u32 tenant_id, u32 addr. prefixlen and tenant_id are
// native byte order to match the program's struct loads; addr stays in network
// byte order (the 4 IPv4 bytes as-is) so the LPM trie prefix-matches CIDRs
// most-significant-byte first.
func egressKeyBytes(e EgressEntry) [12]byte {
	var b [12]byte
	binary.NativeEndian.PutUint32(b[0:4], e.PrefixLen)
	binary.NativeEndian.PutUint32(b[4:8], e.TenantID)
	copy(b[8:12], e.Addr[:])
	return b
}
