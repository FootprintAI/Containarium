package netbpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Map / program / section names — must match SEC(".maps") names and the
// program section in experimental/ebpf-phaseA/netpolicy.bpf.c.
const (
	progNetpolicy       = "netpolicy_ingress"
	progNetpolicyEgress = "netpolicy_egress"
	mapVethPolicy       = "veth_policy"
	mapEgressCIDR       = "egress_cidr"
	mapIPTenant         = "ip_tenant"
	mapStats            = "stats"
	mapEvents           = "events"
	mapFlows            = "flows"
	mapDenyCIDR         = "deny_cidr"
	mapSignatures       = "signatures"
	mapSigConfig        = "sig_config"
	statSeen            = uint32(0)
	statWouldDeny       = uint32(1)
	statsEntryCount     = 2
)

// Loader owns a loaded netpolicy BPF collection and the per-veth TCX links it
// has attached. It is the Phase A productionization of cmd/ebpf-phase0: instead
// of a counter it loads the real policy program, populates the policy maps, and
// attaches the program to each managed container's host veth in TC_INGRESS.
//
// Linux-only at runtime: cilium/ebpf compiles on every platform (so the daemon
// builds on a dev mac), but Load/Attach return errors on non-Linux kernels.
type Loader struct {
	coll        *ebpf.Collection
	links       map[int]link.Link // ifindex -> TCX ingress link
	egressLinks map[int]link.Link // ifindex -> TCX egress link (#631 reply accounting)
}

// Resolve loads the netpolicy BPF object from the operator-supplied source. The
// value comes from CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT and is interpreted as:
//
//   - "embedded" / "1" / "true" / "yes" / "on" → the object compiled into this
//     binary at build time (release binaries bundle it; see `make build-bpf`).
//   - anything else → a filesystem path to a netpolicy.bpf.o.
//
// This lets release builds enable the feature with a single env flag while a
// custom/locally-built object can still be pointed at by path.
func Resolve(value string) (*Loader, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "embedded", "1", "true", "yes", "on":
		obj := EmbeddedObject()
		if len(obj) == 0 {
			return nil, fmt.Errorf("netbpf: no embedded BPF object in this build " +
				"(release binaries bundle it; for a custom build run `make build-bpf` then " +
				"build with -tags embed_bpf, or set CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT to a netpolicy.bpf.o path)")
		}
		return LoadFromBytes(obj)
	default:
		return Load(value)
	}
}

// Load reads the compiled BPF object at objPath and loads the collection. Build
// the object with:
//
//	clang -O2 -g -target bpfel -I/usr/include/$(uname -m)-linux-gnu \
//	    -c experimental/ebpf-phaseA/netpolicy.bpf.c -o netpolicy.bpf.o
func Load(objPath string) (*Loader, error) {
	if _, err := os.Stat(objPath); err != nil {
		return nil, fmt.Errorf("netbpf: BPF object %q: %w", objPath, err)
	}
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("netbpf: load spec: %w", err)
	}
	return newLoaderFromSpec(spec)
}

// LoadFromBytes loads the collection from an in-memory BPF object — used for the
// object embedded into the binary (Resolve "embedded"). Same verification as
// Load.
func LoadFromBytes(obj []byte) (*Loader, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return nil, fmt.Errorf("netbpf: load spec from embedded object: %w", err)
	}
	return newLoaderFromSpec(spec)
}

// newLoaderFromSpec instantiates the collection from a parsed spec and verifies
// the expected program + maps are present. Shared by Load and LoadFromBytes.
func newLoaderFromSpec(spec *ebpf.CollectionSpec) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("netbpf: RemoveMemlock: %w", err)
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
	// progNetpolicyEgress is OPTIONAL: an object built before #631 lacks it, and
	// the loader still works (reply-byte accounting just stays off). AttachVethEgress
	// no-ops when it's absent.
	return &Loader{
		coll:        coll,
		links:       make(map[int]link.Link),
		egressLinks: make(map[int]link.Link),
	}, nil
}

// hasEgressProgram reports whether the loaded object carries the reply-accounting
// egress program (#631).
func (l *Loader) hasEgressProgram() bool { return l.coll.Programs[progNetpolicyEgress] != nil }

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

// AttachVethEgress attaches the reply-accounting program to a container's host
// veth in TC_EGRESS via TCX (#631), so the container's receive-direction bytes
// are tallied. Idempotent per ifindex. No-ops when the loaded object predates
// #631 (no egress program) — reply bytes then stay 0 rather than failing.
func (l *Loader) AttachVethEgress(ifindex int) error {
	if !l.hasEgressProgram() {
		return nil
	}
	if _, ok := l.egressLinks[ifindex]; ok {
		return nil
	}
	lnk, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   l.coll.Programs[progNetpolicyEgress],
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("netbpf: attach TCX egress on ifindex %d: %w", ifindex, err)
	}
	l.egressLinks[ifindex] = lnk
	return nil
}

// DetachVeth removes both programs from a veth (e.g. on container stop/delete).
func (l *Loader) DetachVeth(ifindex int) error {
	var errs []error
	if lnk, ok := l.links[ifindex]; ok {
		delete(l.links, ifindex)
		if err := lnk.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if lnk, ok := l.egressLinks[ifindex]; ok {
		delete(l.egressLinks, ifindex)
		if err := lnk.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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

// DeleteEgress removes an egress allow-list LPM entry. Used by the reconcile
// loop to converge the map when a CIDR is removed from a policy — a stale allow
// entry is a security hole once a tenant is in enforce mode. A missing key is
// not an error (the desired state is already reached).
func (l *Loader) DeleteEgress(e EgressEntry) error {
	key := egressKeyBytes(e)
	if err := l.coll.Maps[mapEgressCIDR].Delete(key[:]); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("netbpf: delete egress_cidr: %w", err)
	}
	return nil
}

// HasDenyRules reports whether the loaded object carries the virtual-patch
// deny_cidr map (#660). Like the flows map it is NOT required by Load — an
// object built before this feature still loads and enforces the allow-list; the
// daemon just skips deny-rule installation until the operator rebuilds
// netpolicy.bpf.o. AddDeny/DeleteDeny error if it's absent.
func (l *Loader) HasDenyRules() bool { return l.coll.Maps[mapDenyCIDR] != nil }

// AddDeny installs (or updates) one virtual-patch deny entry: an LPM key
// (tenant + CIDR) mapping to the rule's port/proto scope. Update is an upsert, so
// changing only a rule's port/proto rewrites the same map slot. Errors if the
// loaded object lacks the deny map (HasDenyRules is false).
func (l *Loader) AddDeny(e DenyEntry) error {
	m := l.coll.Maps[mapDenyCIDR]
	if m == nil {
		return fmt.Errorf("netbpf: deny_cidr map not present (rebuild netpolicy.bpf.o?)")
	}
	key := denyKeyBytes(e.Key())
	val := denyValueBytes(e)
	if err := m.Update(key[:], val[:], ebpf.UpdateAny); err != nil {
		return fmt.Errorf("netbpf: update deny_cidr: %w", err)
	}
	return nil
}

// DeleteDeny removes a virtual-patch deny entry by its LPM key. Used by the
// reconcile loop to converge the map when a deny rule is removed (or expires) —
// a stale deny entry would keep blocking traffic after the operator cleared the
// rule. A missing key is not an error (desired state already reached).
func (l *Loader) DeleteDeny(k DenyKey) error {
	m := l.coll.Maps[mapDenyCIDR]
	if m == nil {
		return fmt.Errorf("netbpf: deny_cidr map not present (rebuild netpolicy.bpf.o?)")
	}
	key := denyKeyBytes(k)
	if err := m.Delete(key[:]); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("netbpf: delete deny_cidr: %w", err)
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

// DeleteIPTenant removes an IP -> tenant mapping. Used by the reconcile loop to
// converge the map when a container's IP is no longer managed (stopped/deleted)
// or is excluded from tagging (e.g. the control plane): a stale tag would let
// the program treat a since-freed or re-purposed IP as a same-tenant peer. A
// missing key is not an error (the desired state is already reached).
func (l *Loader) DeleteIPTenant(ip [4]byte) error {
	key := binary.LittleEndian.Uint32(ip[:])
	if err := l.coll.Maps[mapIPTenant].Delete(&key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("netbpf: delete ip_tenant: %w", err)
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

// HasFlowAccounting reports whether the loaded object carries the per-flow
// accounting map (#627). It is intentionally NOT required by Load — an older
// object built before this feature still loads and enforces; the daemon just
// skips the traffic-flow poll. The operator rebuilds netpolicy.bpf.o to enable
// it.
func (l *Loader) HasFlowAccounting() bool { return l.coll.Maps[mapFlows] != nil }

// Flows snapshots the per-flow accounting map (#627): every observed flow on a
// managed veth with its cumulative byte/packet tally and first/last timestamps.
// Read-only — entries are aged out by the map's LRU eviction and the caller's
// idle pruning, NOT drained here, so the cumulative counters stay monotonic for
// the active-connection view. Returns an error if the object lacks the map
// (HasFlowAccounting is false).
func (l *Loader) Flows() ([]FlowRecord, error) {
	m := l.coll.Maps[mapFlows]
	if m == nil {
		return nil, fmt.Errorf("netbpf: flows map not present (rebuild netpolicy.bpf.o?)")
	}
	// Size the value buffer to the map's actual ValueSize so Lookup matches the
	// kernel map whether the object is the v1 (32-byte) or current (48-byte, with
	// rx) flow_stat (#631). decodeFlowStat tolerates either length.
	keyBuf := make([]byte, flowKeySize)
	valBuf := make([]byte, m.ValueSize())
	var out []FlowRecord
	it := m.Iterate()
	for it.Next(&keyBuf, &valBuf) {
		var rec FlowRecord
		if err := decodeFlowKey(keyBuf, &rec); err != nil {
			return nil, err
		}
		if err := decodeFlowStat(valBuf, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("netbpf: iterate flows: %w", err)
	}
	return out, nil
}

// DeleteFlow removes one entry from the flows map, identified by rec's 5-tuple
// key. The idle reaper (#632) calls this to "persist + forget" a quiesced flow
// after writing its final counters to history, so a flow that simply went quiet
// doesn't linger in the LRU map until eviction (which, on a far-from-full map,
// effectively never happens). A key that's already gone is not an error.
func (l *Loader) DeleteFlow(rec FlowRecord) error {
	m := l.coll.Maps[mapFlows]
	if m == nil {
		return fmt.Errorf("netbpf: flows map not present (rebuild netpolicy.bpf.o?)")
	}
	if err := m.Delete(encodeFlowKey(rec)); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("netbpf: delete flow: %w", err)
	}
	return nil
}

// encodeFlowKey renders rec's 5-tuple as the 20-byte `struct flow_key` wire
// layout — the exact inverse of decodeFlowKey (native-endian fields + 3 zero pad
// bytes, matching the kernel's zero-initialised key). Used to address a specific
// flow for deletion.
func encodeFlowKey(rec FlowRecord) []byte {
	b := make([]byte, flowKeySize)
	binary.NativeEndian.PutUint32(b[0:4], rec.Ifindex)
	binary.NativeEndian.PutUint32(b[4:8], rec.Saddr)
	binary.NativeEndian.PutUint32(b[8:12], rec.Daddr)
	binary.NativeEndian.PutUint16(b[12:14], rec.Sport)
	binary.NativeEndian.PutUint16(b[14:16], rec.Dport)
	b[16] = rec.Proto
	// b[17:20] padding stays zero
	return b
}

// Close detaches every veth link (ingress + egress) and frees the collection.
func (l *Loader) Close() error {
	var errs []error
	for idx, lnk := range l.links {
		if err := lnk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close link ifindex %d: %w", idx, err))
		}
	}
	for idx, lnk := range l.egressLinks {
		if err := lnk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close egress link ifindex %d: %w", idx, err))
		}
	}
	l.links = nil
	l.egressLinks = nil
	if l.coll != nil {
		l.coll.Close()
		l.coll = nil
	}
	return errors.Join(errs...)
}

// --- byte-layout helpers (kept next to the C struct definitions they mirror) ---

// vethPolicyValue serializes a PolicyConfig into the 8-byte `struct policy_cfg`
// layout: u32 tenant_id, u8 mode, u8 allow_intra, u8 allow_metadata, u8 pad.
// Native byte order (the kernel reads the map value with native loads).
func vethPolicyValue(cfg PolicyConfig) [8]byte {
	var b [8]byte
	binary.NativeEndian.PutUint32(b[0:4], cfg.TenantID)
	b[4] = cfg.Mode
	b[5] = cfg.AllowIntra
	b[6] = cfg.AllowMetadata
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

// denyKeyBytes serializes a DenyKey into the 12-byte `struct egress_key` layout
// the deny_cidr LPM trie shares with egress_cidr (u32 prefixlen, u32 tenant_id,
// 4 addr bytes). Same byte-order rules as egressKeyBytes.
func denyKeyBytes(k DenyKey) [12]byte {
	var b [12]byte
	binary.NativeEndian.PutUint32(b[0:4], k.PrefixLen)
	binary.NativeEndian.PutUint32(b[4:8], k.TenantID)
	copy(b[8:12], k.Addr[:])
	return b
}

// denyValueBytes serializes a DenyEntry's scope into the 4-byte `struct deny_val`
// layout: u16 port (host byte order — the program compares it against the ntoh'd
// dport), u8 proto, u8 flags (reserved 0).
func denyValueBytes(e DenyEntry) [4]byte {
	var b [4]byte
	binary.NativeEndian.PutUint16(b[0:2], e.Port)
	b[2] = e.Proto
	return b
}
