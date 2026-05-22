// Phase 0 — bridge-attach validation for the eBPF network
// isolation design (see docs/security/NETWORK-ISOLATION-DESIGN.md).
//
// THROWAWAY. The only purpose is to confirm:
//   1. A tc-bpf program can be attached to incusbr0 cleanly.
//   2. The program sees container-to-container packets.
//   3. Attach/detach doesn't disrupt existing Incus container networking.
//
// If those three hold, Phase A productionalizes; if any fails, the
// design needs to be revised before the user-facing work starts.
//
// Build:
//   clang -O2 -g -target bpf -c counter.bpf.c -o counter.bpf.o
//
// Requires kernel ≥ 5.4 with BPF + CLS_BPF enabled (Ubuntu 24.04 is
// fine out of the box).

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

// Two array-typed counters, one per direction. Array maps are the
// cheapest BPF map type — fixed-size, no allocation per packet,
// __sync_fetch_and_add does the increment atomically.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} pkt_counter SEC(".maps");

// Index 0 = ingress (packets arriving at the bridge),
// Index 1 = egress  (packets leaving the bridge).
//
// "Ingress" and "egress" here are from the BRIDGE'S perspective,
// not the container's — they're the tc direction names. A packet
// alice→bob inside the same backend hits the bridge twice: once
// as it leaves alice's veth (bridge ingress), once as it enters
// bob's veth (bridge egress).
//
// Phase 0 success criterion: BOTH counters increment when alice
// pings bob.

SEC("classifier/ingress")
int count_ingress(struct __sk_buff *skb) {
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&pkt_counter, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
    return TC_ACT_OK;  // never drop; observation only.
}

SEC("classifier/egress")
int count_egress(struct __sk_buff *skb) {
    __u32 key = 1;
    __u64 *val = bpf_map_lookup_elem(&pkt_counter, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
    return TC_ACT_OK;
}

// Required by the verifier so the program loads at all. Dual
// license keeps the door open whether we GPL-only-stamp the
// production program later or not.
char LICENSE[] SEC("license") = "Dual MIT/GPL";
