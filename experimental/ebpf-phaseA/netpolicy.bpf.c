// Phase A — per-container-veth network-policy program for the eBPF
// network isolation design (see docs/security/NETWORK-ISOLATION-DESIGN.md).
//
// Attach point: each container's host-side veth, TC_INGRESS. Per the Phase 0
// findings, the veth ingress hook sees the container's ENTIRE outbound — the
// sender side of every flow — which is the only reliable observation/enforcement
// point for bridge-forwarded inter-container traffic.
//
// Phase A is OBSERVATION ONLY (log_only): the program evaluates each flow
// against the sender's tenant policy and, for flows that WOULD be denied,
// emits a perf event (and bumps a would-deny counter) — but always returns
// TC_ACT_OK. Nothing is dropped. Phase B flips would-deny to TC_ACT_SHOT when
// the per-veth mode is ENFORCE.
//
// Build (the multiarch -I lets clang's bpf target find <asm/types.h>):
//   clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu \
//       -c netpolicy.bpf.c -o netpolicy.bpf.o
//
// Requires kernel ≥ 5.4 (LPM_TRIE + perf_event_output). Ubuntu 24.04 is fine.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Mode values — mirror pb.NetworkPolicyMode (config.proto). Phase A only ever
// loads LOG_ONLY here; ENFORCE is wired but the drop path is Phase B.
#define MODE_LOG_ONLY 1
#define MODE_ENFORCE  2

// Per-veth policy config, keyed by the veth's host ifindex. The loader writes
// one entry per managed container veth.
struct policy_cfg {
    __u32 tenant_id;     // the owning tenant (sender side)
    __u8  mode;          // MODE_LOG_ONLY | MODE_ENFORCE
    __u8  allow_intra;   // 1 = same-tenant container↔container allowed
    __u8  pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                 // host veth ifindex
    __type(value, struct policy_cfg);
    __uint(max_entries, 4096);
} veth_policy SEC(".maps");

// Egress allow-list as an LPM trie, scoped per tenant: the key carries the
// tenant_id in its high bits followed by the destination prefix, so a lookup
// only matches CIDRs the sender's tenant is allowed to reach. prefixlen counts
// the full tenant_id (32 bits) + the IPv4 prefix bits.
struct egress_key {
    __u32 prefixlen;     // 32 + cidr_bits
    __u32 tenant_id;     // big-endian-irrelevant: exact-matched, 32 prefix bits
    __u32 addr;          // network byte order, masked to cidr_bits
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct egress_key);
    __type(value, __u8);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} egress_cidr SEC(".maps");

// Destination-IP → tenant_id for intra-backend traffic. The loader populates
// this from every managed container's IP, so the program can tell "dst is
// another container of tenant T" from "dst is external".
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                 // dst IPv4 (network byte order)
    __type(value, __u32);               // tenant_id
    __uint(max_entries, 4096);
} ip_tenant SEC(".maps");

// Stats counters the validator reads (like Phase 0). 0=seen, 1=would_deny.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} stats SEC(".maps");

#define STAT_SEEN       0
#define STAT_WOULD_DENY 1

// Perf event ring for denied flows; the daemon's consumer turns each into an
// audit row (action=net_deny).
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Wire shape of a denied-flow event. Kept in lockstep with the Go decoder in
// loader.go (denyEvent).
struct deny_event {
    __u32 ifindex;
    __u32 tenant_id;
    __u32 saddr;         // network byte order
    __u32 daddr;
    __u16 dport;         // host byte order
    __u8  proto;
    __u8  pad;
};

static __always_inline void bump(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

SEC("classifier/netpolicy")
int netpolicy_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Only manage IPv4 for Phase A. Anything else passes untouched.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Which container is this? Look up the veth's policy by ingress ifindex.
    __u32 ifindex = skb->ingress_ifindex;
    struct policy_cfg *cfg = bpf_map_lookup_elem(&veth_policy, &ifindex);
    if (!cfg)
        return TC_ACT_OK; // unmanaged veth — not ours to police.

    bump(STAT_SEEN);

    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;

    // Decide whether this flow is allowed under the sender's policy.
    int allowed = 0;

    __u32 *dst_tenant = bpf_map_lookup_elem(&ip_tenant, &daddr);
    if (dst_tenant) {
        // Intra-backend: destination is another managed container. Allowed only
        // if it's the same tenant and intra-tenant traffic is permitted.
        if (*dst_tenant == cfg->tenant_id && cfg->allow_intra)
            allowed = 1;
    } else {
        // External destination: allowed iff it matches the tenant's egress
        // allow-list.
        struct egress_key k = {};
        k.prefixlen = 32 + 32; // full tenant match + full /32 dst (LPM shortens)
        k.tenant_id = cfg->tenant_id;
        k.addr = daddr;
        if (bpf_map_lookup_elem(&egress_cidr, &k))
            allowed = 1;
    }

    if (allowed)
        return TC_ACT_OK;

    // Would-deny. Record + emit, but only drop in ENFORCE (Phase B).
    bump(STAT_WOULD_DENY);

    struct deny_event ev = {};
    ev.ifindex = ifindex;
    ev.tenant_id = cfg->tenant_id;
    ev.saddr = saddr;
    ev.daddr = daddr;
    ev.proto = ip->protocol;

    // Best-effort L4 dport for the audit row. Bounds-checked for the verifier.
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) <= data_end)
            ev.dport = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)(udp + 1) <= data_end)
            ev.dport = bpf_ntohs(udp->dest);
    }

    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

    if (cfg->mode == MODE_ENFORCE)
        return TC_ACT_SHOT; // Phase B path; Phase A never sets ENFORCE here.
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
