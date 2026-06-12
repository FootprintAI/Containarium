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

// Deny reasons carried in deny_event.reason — mirror netbpf.DenyReason* in Go.
// An older loader that reads only the first 19 bytes ignores it; the byte reuses
// the struct's former pad, so the wire size is unchanged.
#define DENY_REASON_POLICY        0  // failed allow-list / intra-tenant / metadata
#define DENY_REASON_VIRTUAL_PATCH 1  // matched an explicit virtual-patch deny rule (#660)
#define DENY_REASON_SIGNATURE     2  // matched a cleartext exploit signature (#661, Tier 2)

// Per-veth policy config, keyed by the veth's host ifindex. The loader writes
// one entry per managed container veth.
struct policy_cfg {
    __u32 tenant_id;     // the owning tenant (sender side)
    __u8  mode;          // MODE_LOG_ONLY | MODE_ENFORCE
    __u8  allow_intra;   // 1 = same-tenant container↔container allowed
    __u8  allow_metadata; // 1 = may reach 169.254.169.254 (default 0 = denied)
    __u8  pad;
};

// Cloud metadata service IP (169.254.169.254). Compared against the packet's
// network-byte-order daddr via bpf_htonl. #315 Phase D.
#define METADATA_IPV4 0xA9FEA9FE

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

// Virtual-patch deny rules (#660). Same tenant-scoped LPM key as egress_cidr,
// but a richer value so a rule can be scoped to a destination port/proto: a CVE
// in a service on a known port can be blocked without blackholing the whole
// host. Evaluated BEFORE the allow logic — deny beats allow. The LPM key is
// CIDR-only (port/proto live in the value), so there is at most ONE deny entry
// per (tenant, CIDR); to block two ports on the same host, deny the host
// outright (port 0 = any) — a documented Tier-1 limitation.
struct deny_val {
    __u16 port;   // host byte order; 0 = any port
    __u8  proto;  // IP protocol number; 0 = any proto
    __u8  flags;  // reserved (0)
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct egress_key);
    __type(value, struct deny_val);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} deny_cidr SEC(".maps");

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

// Per-flow accounting (issue #627). Every observed flow on a managed veth gets a
// cumulative bytes/packets tally here, keyed by its 5-tuple, so the daemon can
// populate the traffic view (src/dst IP + byte counts) straight from eBPF —
// independent of conntrack accounting and the IP→container cache. Attribution is
// exact: the ifindex in the key maps 1:1 to a container. Recorded for ALLOWED and
// would-deny flows alike (it's usage accounting, not a policy decision).
//
// The veth ingress hook sees the container's outbound (sender) side, so the
// packets/bytes counts are the container's EGRESS. The reply direction
// (peer→container) is captured by a second program on the veth's TC_EGRESS hook
// (#631), tallied into rx_packets/rx_bytes on the SAME flow entry (the egress
// program rebuilds the request-oriented key by swapping the reply's tuple), so a
// flow carries both directions.
//
// LRU_HASH so a burst of short-lived flows self-evicts under pressure rather than
// filling the map; the daemon reads it on a poll and ages out idle entries.
struct flow_key {
    __u32 ifindex;   // host veth — attribution handle (1:1 with a container)
    __u32 saddr;     // source IPv4, network byte order
    __u32 daddr;     // destination IPv4, network byte order
    __u16 sport;     // host byte order
    __u16 dport;     // host byte order
    __u8  proto;     // IP protocol number
    __u8  pad[3];
};

// flow_stat: tx_* (packets/bytes) are the container's egress, observed on the
// veth ingress hook; rx_* are the reply direction, observed on the veth egress
// hook (#631). rx fields are APPENDED so an older 32-byte value (pre-#631) still
// decodes — the Go reader treats missing rx as 0.
struct flow_stat {
    __u64 packets;     // tx: container → peer
    __u64 bytes;
    __u64 first_ns;    // bpf_ktime_get_ns at first packet (monotonic)
    __u64 last_ns;     // bpf_ktime_get_ns at most recent packet (monotonic)
    __u64 rx_packets;  // reply: peer → container (#631)
    __u64 rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_stat);
    __uint(max_entries, 65536);
} flows SEC(".maps");

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
    __u8  reason;        // DENY_REASON_* (was pad; size unchanged) #660
    __u16 sig_id;        // matched signature id when reason==SIGNATURE, else 0 (#661)
    __u16 pad2;
};

// --- Tier 2 (#661): cleartext exploit-signature scanning --------------------
//
// The container's INBOUND direction (host→container, seen on the veth TC_EGRESS
// hook) is scanned for a small set of operator-curated cleartext signatures, to
// virtually patch a vulnerable service in the container (a WAF-style block of
// e.g. a Log4Shell `${jndi:` request) before the vendor fix ships.
//
// The verifier-feasible shape (proved out in sigscan-proto.bpf.c): one bpf_loop
// over the flattened (signature × offset) space with only the pattern-compare
// loop unrolled, the payload window in a per-CPU scratch map re-looked-up inside
// the callback, and tiered CONSTANT-size payload loads (a variable length gets
// re-derived from skb arithmetic past every guard and rejected). Best-effort by
// construction: single packet (no reassembly), cleartext only (TLS is opaque),
// first SCAN_WINDOW bytes only.
#define SIG_MAX_LEN   32   // bytes per signature pattern
#define SIG_MAX_COUNT 32   // signature slots scanned per packet
#define SCAN_WINDOW   256  // payload bytes scanned (power of two for index masking)
#define SIG_SCAN_MIN  32   // don't bother scanning a payload shorter than this

struct signature {
    __u8  len;                 // active bytes in pat, 1..SIG_MAX_LEN (0 = empty slot)
    __u8  enabled;             // 1 = scan this slot
    __u16 id;                  // signature id (>0), echoed on a match
    __u8  pat[SIG_MAX_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct signature);
    __uint(max_entries, SIG_MAX_COUNT);
} signatures SEC(".maps");

// Per-CPU scratch for the copied payload window (per-CPU so concurrent packets on
// different CPUs don't clobber it; one entry suffices).
struct scan_scratch {
    __u8 buf[SCAN_WINDOW];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct scan_scratch);
    __uint(max_entries, 1);
} scan_buf SEC(".maps");

// sig_config[0] gates the whole scan: 0 = skip it entirely (the default, so the
// bpf_loop cost is never paid on hosts that haven't opted into Tier 2). The
// loader sets it to 1 only once signatures are populated.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} sig_config SEC(".maps");

static __always_inline int sig_scan_enabled(void) {
    __u32 zero = 0;
    __u32 *on = bpf_map_lookup_elem(&sig_config, &zero);
    return on && *on;
}

struct sig_scan_ctx {
    __u32 n;        // valid bytes in the window
    __u32 match_id; // out: matched signature id, or 0
};

// sig_match_at is the bpf_loop callback over the flattened (signature, offset)
// space. The verifier checks it ONCE regardless of trip count, so there is no
// back-edge to mistake for an infinite loop.
static long sig_match_at(__u32 idx, void *vctx) {
    struct sig_scan_ctx *c = vctx;
    if (c->match_id)
        return 1; // already matched — stop

    __u32 si = idx / SCAN_WINDOW;        // signature slot
    __u32 i  = idx & (SCAN_WINDOW - 1);  // start offset in the window

    struct signature *s = bpf_map_lookup_elem(&signatures, &si);
    if (!s || !s->enabled)
        return 0;
    __u32 slen = s->len;
    if (slen == 0 || slen > SIG_MAX_LEN || i + slen > c->n)
        return 0;

    __u32 zero = 0;
    struct scan_scratch *sc = bpf_map_lookup_elem(&scan_buf, &zero);
    if (!sc)
        return 1;

    int miss = 0;
#pragma clang loop unroll(full)
    for (__u32 j = 0; j < SIG_MAX_LEN; j++) {
        if (j < slen) {
            __u32 k = (i + j) & (SCAN_WINDOW - 1); // static bound; i+slen<=n<=WINDOW so never wraps a real compare
            if (sc->buf[k] != s->pat[j])
                miss = 1;
        }
    }
    if (!miss) {
        c->match_id = s->id;
        return 1;
    }
    return 0;
}

// scan_inbound copies up to SCAN_WINDOW payload bytes (largest fitting power-of-
// two via tiered constant loads) and searches for any enabled signature. Returns
// the matched id, or 0.
static __always_inline __u32 scan_inbound(struct __sk_buff *skb, __u32 off, __u32 avail) {
    __u32 zero = 0;
    struct scan_scratch *sc = bpf_map_lookup_elem(&scan_buf, &zero);
    if (!sc)
        return 0;
    __u32 n;
    // Each load size is a literal constant (a variable size is rejected — see the
    // prototype notes). Largest window that fits the payload wins.
    if (avail >= 256) {
        if (bpf_skb_load_bytes(skb, off, sc->buf, 256) < 0)
            return 0;
        n = 256;
    } else if (avail >= 128) {
        if (bpf_skb_load_bytes(skb, off, sc->buf, 128) < 0)
            return 0;
        n = 128;
    } else if (avail >= 64) {
        if (bpf_skb_load_bytes(skb, off, sc->buf, 64) < 0)
            return 0;
        n = 64;
    } else if (avail >= SIG_SCAN_MIN) {
        if (bpf_skb_load_bytes(skb, off, sc->buf, SIG_SCAN_MIN) < 0)
            return 0;
        n = SIG_SCAN_MIN;
    } else {
        return 0; // too short to be worth scanning
    }
    struct sig_scan_ctx ctx = {.n = n, .match_id = 0};
    bpf_loop(SIG_MAX_COUNT * SCAN_WINDOW, sig_match_at, &ctx, 0);
    return ctx.match_id;
}

static __always_inline void bump(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

// account_flow tallies one packet against its 5-tuple in the flows map (#627).
// First packet of a flow creates the entry; subsequent packets bump the
// cumulative byte/packet counters and the last-seen timestamp.
static __always_inline void account_flow(struct __sk_buff *skb, __u32 ifindex,
                                         __u32 saddr, __u32 daddr,
                                         __u16 sport, __u16 dport, __u8 proto) {
    struct flow_key fk = {};
    fk.ifindex = ifindex;
    fk.saddr = saddr;
    fk.daddr = daddr;
    fk.sport = sport;
    fk.dport = dport;
    fk.proto = proto;

    __u64 now = bpf_ktime_get_ns();
    __u64 len = skb->len; // full L2+ length of this packet

    struct flow_stat *fs = bpf_map_lookup_elem(&flows, &fk);
    if (fs) {
        __sync_fetch_and_add(&fs->packets, 1);
        __sync_fetch_and_add(&fs->bytes, len);
        fs->last_ns = now;
        return;
    }
    struct flow_stat nfs = {};
    nfs.packets = 1;
    nfs.bytes = len;
    nfs.first_ns = now;
    nfs.last_ns = now;
    bpf_map_update_elem(&flows, &fk, &nfs, BPF_ANY);
}

// account_reply tallies one reply packet (peer → container, seen on the veth
// TC_EGRESS hook) into the rx_* counters of its flow (#631). The caller passes
// the key already rebuilt in REQUEST orientation (src=container, dst=peer), so
// the reply lands on the same entry the ingress hook created for the request.
// If the request entry doesn't exist yet (reply observed first), create it with
// only the rx counters set.
static __always_inline void account_reply(struct __sk_buff *skb, __u32 ifindex,
                                          __u32 saddr, __u32 daddr,
                                          __u16 sport, __u16 dport, __u8 proto) {
    struct flow_key fk = {};
    fk.ifindex = ifindex;
    fk.saddr = saddr;
    fk.daddr = daddr;
    fk.sport = sport;
    fk.dport = dport;
    fk.proto = proto;

    __u64 now = bpf_ktime_get_ns();
    __u64 len = skb->len;

    struct flow_stat *fs = bpf_map_lookup_elem(&flows, &fk);
    if (fs) {
        __sync_fetch_and_add(&fs->rx_packets, 1);
        __sync_fetch_and_add(&fs->rx_bytes, len);
        fs->last_ns = now;
        return;
    }
    struct flow_stat nfs = {};
    nfs.rx_packets = 1;
    nfs.rx_bytes = len;
    nfs.first_ns = now;
    nfs.last_ns = now;
    bpf_map_update_elem(&flows, &fk, &nfs, BPF_ANY);
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

    // Parse L4 ports once (host byte order), bounds-checked for the verifier.
    // Used both for per-flow accounting (#627) and the deny audit event below.
    // ICMP and other L4 protocols carry 0 ports. NOTE: assumes no IP options
    // (ihl=5), same as the deny path historically did.
    __u16 sport = 0, dport = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) <= data_end) {
            sport = bpf_ntohs(tcp->source);
            dport = bpf_ntohs(tcp->dest);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)(udp + 1) <= data_end) {
            sport = bpf_ntohs(udp->source);
            dport = bpf_ntohs(udp->dest);
        }
    }

    // Usage accounting for the traffic view (#627): tally EVERY flow, allowed or
    // not. Done before the policy decision so a would-deny flow is still counted.
    account_flow(skb, ifindex, saddr, daddr, sport, dport, ip->protocol);

    // Virtual-patch deny rules (#660) override EVERYTHING: a destination that
    // matches a tenant's deny rule (optionally scoped to dport/proto) is blocked
    // regardless of the allow-list or metadata opt-in. Checked first so neither
    // an allow CIDR nor allow_metadata can win against an explicit virtual patch.
    __u8 deny_reason = DENY_REASON_POLICY;
    int vpatch_deny = 0;
    {
        struct egress_key dk = {};
        dk.prefixlen = 32 + 32; // full tenant match + /32 dst (LPM shortens to the rule's prefix)
        dk.tenant_id = cfg->tenant_id;
        dk.addr = daddr;
        struct deny_val *dv = bpf_map_lookup_elem(&deny_cidr, &dk);
        if (dv &&
            (dv->port == 0 || dv->port == dport) &&
            (dv->proto == 0 || dv->proto == ip->protocol)) {
            vpatch_deny = 1;
            deny_reason = DENY_REASON_VIRTUAL_PATCH;
        }
    }

    // Decide whether this flow is allowed under the sender's policy.
    int allowed = 0;

    if (vpatch_deny) {
        allowed = 0; // explicit virtual-patch deny — skip the allow checks entirely.
    } else
    // Cloud metadata service is deny-by-default and overrides the egress
    // allow-list: even a broad allow CIDR must not expose 169.254.169.254
    // unless the tenant explicitly opted in (#315 Phase D). Checked first so an
    // allow can't win.
    if (daddr == bpf_htonl(METADATA_IPV4)) {
        allowed = cfg->allow_metadata ? 1 : 0;
    } else {
        __u32 *dst_tenant = bpf_map_lookup_elem(&ip_tenant, &daddr);
        if (dst_tenant) {
            // Intra-backend: destination is another managed container. Allowed
            // only if it's the same tenant and intra-tenant traffic is permitted.
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
    ev.dport = dport; // parsed once above
    ev.reason = deny_reason; // policy miss vs. explicit virtual-patch deny (#660)

    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

    if (cfg->mode == MODE_ENFORCE)
        return TC_ACT_SHOT; // Phase B path; Phase A never sets ENFORCE here.
    return TC_ACT_OK;
}

// netpolicy_egress runs on the container veth's TC_EGRESS hook — packets the
// host transmits TOWARD the container, i.e. the container's RECEIVE direction
// (#631). It does accounting ONLY (no policy: enforcement happens on the
// sender's egress, which the ingress hook above already sees); it always passes.
//
// The reply packet's tuple is the mirror of the request: src=peer, dst=container.
// To land the rx bytes on the same flow entry the request created, rebuild the
// request-oriented key by swapping — saddr=ip->daddr (container), daddr=ip->saddr
// (peer), sport=reply dport, dport=reply sport.
SEC("classifier/netpolicy_egress")
int netpolicy_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // On the egress hook the veth is the transmit interface: skb->ifindex
    // (ingress_ifindex is 0 here). Only manage known veths.
    __u32 ifindex = skb->ifindex;
    struct policy_cfg *cfg = bpf_map_lookup_elem(&veth_policy, &ifindex);
    if (!cfg)
        return TC_ACT_OK;

    __u16 sport = 0, dport = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) <= data_end) {
            sport = bpf_ntohs(tcp->source);
            dport = bpf_ntohs(tcp->dest);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)(udp + 1) <= data_end) {
            sport = bpf_ntohs(udp->source);
            dport = bpf_ntohs(udp->dest);
        }
    }

    // Swap to request orientation: container is the reply's destination.
    account_reply(skb, ifindex,
                  ip->daddr,  // saddr (request) = reply dst = container
                  ip->saddr,  // daddr (request) = reply src = peer
                  dport,      // sport (request) = reply dport = container port
                  sport,      // dport (request) = reply sport = peer port
                  ip->protocol);

    // Tier 2 (#661): scan the INBOUND payload (peer→container) for cleartext
    // exploit signatures and virtually-patch the container's service. TCP only,
    // and only when the operator has enabled scanning (gates the bpf_loop cost).
    if (ip->protocol == IPPROTO_TCP && sig_scan_enabled()) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) <= data_end) {
            __u32 tcp_hlen = tcp->doff * 4;
            __u32 payload_off = sizeof(*eth) + sizeof(*ip) + tcp_hlen;
            __u32 skb_len = skb->len;
            if (tcp_hlen >= sizeof(*tcp) && payload_off < skb_len) {
                __u32 sig = scan_inbound(skb, payload_off, skb_len - payload_off);
                if (sig) {
                    bump(STAT_WOULD_DENY);
                    struct deny_event ev = {};
                    ev.ifindex = ifindex;
                    ev.tenant_id = cfg->tenant_id;
                    ev.saddr = ip->saddr; // peer (the attacker)
                    ev.daddr = ip->daddr; // the container
                    ev.proto = ip->protocol;
                    ev.dport = dport; // the container's service port (tcp->dest)
                    ev.reason = DENY_REASON_SIGNATURE;
                    ev.sig_id = (__u16)sig;
                    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
                    if (cfg->mode == MODE_ENFORCE)
                        return TC_ACT_SHOT; // drop the exploit before it reaches the service
                }
            }
        }
    }
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
