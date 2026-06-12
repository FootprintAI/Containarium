// Tier 2 (#661) VERIFIER PROTOTYPE — bounded cleartext signature scanning.
//
// Standalone and NOT loaded by the daemon. Its only job is to prove the kernel
// verifier accepts the risky core of Tier 2 — copying a payload window and
// running a bounded substring search against a signature map — before we wire it
// into the production netpolicy.bpf.c. eBPF can't run on the dev mac, so this is
// validated on a Linux backend:
//
//   clang -O2 -g -target bpfel -I/usr/include/$(uname -m)-linux-gnu \
//       -c sigscan-proto.bpf.c -o /tmp/sigscan.o
//   sudo bpftool prog loadall /tmp/sigscan.o /sys/fs/bpf/sigscan type tc
//   # LOADED OK => the verifier accepts the scan; clean up: sudo rm -rf /sys/fs/bpf/sigscan
//
// Design notes from three rejected attempts (kept so the next person doesn't
// repeat them):
//   - Naive nested loops with a variable inner bound  -> "infinite loop detected"
//     (clang -O2 makes a back-edge the verifier can't prove terminates).
//   - Fully unrolling the offset+pattern loops        -> still "infinite loop" on
//     the signature counter AND a 600 KB object. Unrolling is a dead end here.
//   - WORKS: a single bpf_loop() over the flattened (signature x offset) space,
//     with only the tiny pattern-compare loop unrolled. bpf_loop is verified
//     ONCE regardless of trip count, so there is no back-edge to mis-analyze. The
//     payload window lives in a PER-CPU scratch map (not the stack), re-looked-up
//     inside the callback, so the verifier always has a clean map-value pointer
//     with a known bound — passing a stack pointer through the callback ctx loses
//     that bound.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Tunables. SCAN_WINDOW must be a power of two (index masking). bpf_loop runs
// SIG_MAX_COUNT * SCAN_WINDOW iterations worst case (8 * 64 = 512).
#define SIG_MAX_LEN   32
#define SIG_MAX_COUNT 32
#define SCAN_WINDOW   256

struct signature {
    __u8  len;                 // active bytes in pat, 1..SIG_MAX_LEN (0 = empty)
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

// Per-CPU scratch for the copied payload window. Per-CPU so concurrent packets on
// different CPUs don't clobber each other; a single entry is enough.
struct scratch {
    __u8 buf[SCAN_WINDOW];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct scratch);
    __uint(max_entries, 1);
} scan_buf SEC(".maps");

struct scan_ctx {
    __u32 n;        // valid bytes in the window
    __u32 match_id; // out: matched signature id, or 0
};

// match_at is the bpf_loop callback. idx flattens (signature, offset): the high
// bits select the signature slot, the low log2(SCAN_WINDOW) bits the start offset.
static long match_at(__u32 idx, void *vctx) {
    struct scan_ctx *c = vctx;
    if (c->match_id)
        return 1; // already matched — stop the loop

    __u32 si = idx / SCAN_WINDOW;          // signature slot
    __u32 i  = idx & (SCAN_WINDOW - 1);    // start offset in the window

    struct signature *s = bpf_map_lookup_elem(&signatures, &si);
    if (!s || !s->enabled)
        return 0;
    __u32 slen = s->len;
    if (slen == 0 || slen > SIG_MAX_LEN || i + slen > c->n)
        return 0; // empty slot, or the pattern can't fit at this offset

    __u32 zero = 0;
    struct scratch *sc = bpf_map_lookup_elem(&scan_buf, &zero);
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

// scan_window copies up to SCAN_WINDOW payload bytes and searches for any enabled
// signature. Returns the matched id, or 0.
static __always_inline __u32 scan_window(struct __sk_buff *skb, __u32 off, __u32 avail) {
    __u32 zero = 0;
    struct scratch *sc = bpf_map_lookup_elem(&scan_buf, &zero);
    if (!sc)
        return 0;
    // v1 uses a CONSTANT-size load: clang kept re-deriving a variable length
    // straight from the skb arithmetic (bypassing every guard) and the verifier
    // rejected the possibly-zero size. A constant size is verifier-trivial. The
    // cost is that only packets carrying a full SCAN_WINDOW of payload are scanned
    // — acceptable for a best-effort cleartext pre-filter (a real WAF is Tier 3),
    // and revisited when porting (a tiered set of constant loads can cover short
    // packets without a variable length).
    if (avail < SCAN_WINDOW)
        return 0;
    if (bpf_skb_load_bytes(skb, off, sc->buf, SCAN_WINDOW) < 0)
        return 0;

    struct scan_ctx ctx = {.n = SCAN_WINDOW, .match_id = 0};
    bpf_loop(SIG_MAX_COUNT * SCAN_WINDOW, match_at, &ctx, 0);
    return ctx.match_id;
}

SEC("classifier/sigscan")
int sigscan(struct __sk_buff *skb) {
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
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    struct tcphdr *tcp = (void *)ip + sizeof(*ip); // assumes ihl=5 (no IP options)
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    __u32 tcp_hlen = tcp->doff * 4;
    if (tcp_hlen < sizeof(*tcp))
        return TC_ACT_OK;
    __u32 payload_off = sizeof(*eth) + sizeof(*ip) + tcp_hlen;
    __u32 skb_len = skb->len;
    if (payload_off >= skb_len)
        return TC_ACT_OK; // no payload

    __u32 id = scan_window(skb, payload_off, skb_len - payload_off);
    // Prototype: prove it verifies; never actually drop. (Production wires id != 0
    // into the would-deny path.)
    if (id)
        return TC_ACT_OK;
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
