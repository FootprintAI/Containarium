package netbpf

import (
	"fmt"

	"github.com/footprintai/containarium/internal/netpolicy"
)

// BPF mode constants — mirror the #defines in
// experimental/ebpf-phaseA/netpolicy.bpf.c, which in turn mirror
// pb.NetworkPolicyMode. Phase A only ever loads ModeLogOnly.
const (
	ModeLogOnly uint8 = 1
	ModeEnforce uint8 = 2
)

// PolicyConfig is the per-veth value the loader writes into the BPF veth_policy
// map (keyed by the container's host veth ifindex). Field layout mirrors
// `struct policy_cfg` in netpolicy.bpf.c.
type PolicyConfig struct {
	TenantID      uint32
	Mode          uint8
	AllowIntra    uint8
	AllowMetadata uint8
}

// EgressEntry is one allowed-egress LPM-trie entry the loader writes into the
// BPF egress_cidr map. It is the tenant-scoped destination prefix the sender's
// policy permits. Field layout mirrors `struct egress_key` in netpolicy.bpf.c
// (prefixlen counts the 32-bit exact tenant match plus the IPv4 prefix bits;
// Addr holds the masked network address in network byte order).
type EgressEntry struct {
	PrefixLen uint32
	TenantID  uint32
	Addr      [4]byte
}

// tenantPrefixBits is the LPM prefix length contributed by the tenant_id field:
// a tenant match is always exact (all 32 bits), then the IPv4 prefix bits
// follow.
const tenantPrefixBits = 32

// CompileConfig renders the per-veth policy config from a CompiledPolicy for a
// caller-assigned tenant ID. Tenant ID assignment (registry vs. hash) is a
// daemon concern resolved at the call site, so this layer takes it explicitly.
func CompileConfig(tenantID uint32, c netpolicy.CompiledPolicy) PolicyConfig {
	mode := uint8(c.Mode) // pb enum values match the C #defines (LOG_ONLY=1, ENFORCE=2)
	if mode != ModeLogOnly && mode != ModeEnforce {
		mode = ModeLogOnly // CompiledPolicy already resolves UNSPECIFIED→LOG_ONLY; belt-and-suspenders
	}
	var allow uint8
	if c.AllowIntraTenant {
		allow = 1
	}
	var meta uint8
	if c.AllowMetadata {
		meta = 1
	}
	return PolicyConfig{TenantID: tenantID, Mode: mode, AllowIntra: allow, AllowMetadata: meta}
}

// CompileEgress renders the tenant's egress allow-list (the already-parsed,
// masked, deduped EgressCIDRs of a CompiledPolicy) into LPM-trie entries.
//
// Phase A is IPv4-only (the BPF program parses IPv4 only); any IPv6 CIDR is
// rejected with an error rather than silently dropped, so a v6 allow-rule can't
// masquerade as effective. EgressDomains are not handled here — the daemon's
// resolver (Phase C) folds resolved domain IPs into the same map.
func CompileEgress(tenantID uint32, c netpolicy.CompiledPolicy) ([]EgressEntry, error) {
	out := make([]EgressEntry, 0, len(c.EgressCIDRs))
	for _, p := range c.EgressCIDRs {
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("netbpf: egress CIDR %s is not IPv4 (Phase A is IPv4-only)", p)
		}
		entry := EgressEntry{
			PrefixLen: tenantPrefixBits + uint32(p.Bits()),
			TenantID:  tenantID,
			Addr:      p.Addr().As4(), // masked network address, network byte order
		}
		out = append(out, entry)
	}
	return out, nil
}
