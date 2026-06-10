package netbpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// FlowRecord is one decoded per-flow accounting entry from the BPF `flows` map
// (issue #627). It carries the flow's 5-tuple — attributed to a container by
// Ifindex — plus the cumulative tally: Packets/Bytes are the container's EGRESS
// (veth ingress hook), RxPackets/RxBytes the reply direction (veth egress hook,
// #631). The wire layout of the key/value must stay in lockstep with `struct
// flow_key` / `struct flow_stat` in experimental/ebpf-phaseA/netpolicy.bpf.c.
type FlowRecord struct {
	Ifindex   uint32
	Saddr     uint32 // source IPv4, network byte order (as carried on the wire)
	Daddr     uint32 // destination IPv4, network byte order
	Sport     uint16 // host byte order
	Dport     uint16 // host byte order
	Proto     uint8  // IP protocol number (1=ICMP, 6=TCP, 17=UDP)
	Packets   uint64 // tx: container → peer (egress)
	Bytes     uint64
	FirstNs   uint64 // bpf_ktime_get_ns at first packet (monotonic; boot-relative)
	LastNs    uint64 // bpf_ktime_get_ns at most recent packet (monotonic)
	RxPackets uint64 // reply: peer → container (#631); 0 if the object predates it
	RxBytes   uint64
}

// flowKeySize is the wire size of `struct flow_key`. flowStatSizeV1 is the
// original tx-only `struct flow_stat` (4×u64); flowStatSize is the current
// layout with the appended rx counters (#631). Decode accepts either — a value
// from an older object (no rx fields) leaves RxPackets/RxBytes at 0.
//
//	flow_key  = u32 ifindex + u32 saddr + u32 daddr + u16 sport + u16 dport + u8 proto + u8[3] pad
//	flow_stat = u64 packets + u64 bytes + u64 first_ns + u64 last_ns [+ u64 rx_packets + u64 rx_bytes]
const (
	flowKeySize    = 20
	flowStatSizeV1 = 32
	flowStatSize   = 48
)

// Src and Dst render the network-byte-order addresses as netip.Addr, matching
// DenyEvent.Src/Dst (the wire value is a __u32 holding the 4 IPv4 bytes in
// network order).
func (f FlowRecord) Src() netip.Addr { return ipFromBE(f.Saddr) }
func (f FlowRecord) Dst() netip.Addr { return ipFromBE(f.Daddr) }

// decodeFlowKey fills the 5-tuple fields of rec from a raw `struct flow_key`.
func decodeFlowKey(b []byte, rec *FlowRecord) error {
	if len(b) < flowKeySize {
		return fmt.Errorf("netbpf: flow key sample too short: %d < %d bytes", len(b), flowKeySize)
	}
	rec.Ifindex = binary.NativeEndian.Uint32(b[0:4])
	rec.Saddr = binary.NativeEndian.Uint32(b[4:8])
	rec.Daddr = binary.NativeEndian.Uint32(b[8:12])
	rec.Sport = binary.NativeEndian.Uint16(b[12:14])
	rec.Dport = binary.NativeEndian.Uint16(b[14:16])
	rec.Proto = b[16]
	return nil
}

// decodeFlowStat fills the counter fields of rec from a raw `struct flow_stat`.
// Accepts both the v1 (tx-only, 32-byte) and current (48-byte, with rx) layouts
// (#631): a v1 value leaves RxPackets/RxBytes at 0.
func decodeFlowStat(b []byte, rec *FlowRecord) error {
	if len(b) < flowStatSizeV1 {
		return fmt.Errorf("netbpf: flow stat sample too short: %d < %d bytes", len(b), flowStatSizeV1)
	}
	rec.Packets = binary.NativeEndian.Uint64(b[0:8])
	rec.Bytes = binary.NativeEndian.Uint64(b[8:16])
	rec.FirstNs = binary.NativeEndian.Uint64(b[16:24])
	rec.LastNs = binary.NativeEndian.Uint64(b[24:32])
	if len(b) >= flowStatSize {
		rec.RxPackets = binary.NativeEndian.Uint64(b[32:40])
		rec.RxBytes = binary.NativeEndian.Uint64(b[40:48])
	}
	return nil
}
