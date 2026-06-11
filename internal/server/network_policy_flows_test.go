package server

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
)

func beIPv4(a, b, c, d byte) uint32 {
	return binary.NativeEndian.Uint32([]byte{a, b, c, d})
}

func TestFlowsToEBPF_AttributesAndMaps(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	records := []netbpf.FlowRecord{
		{ // managed veth 59 -> web-container
			Ifindex:   59,
			Saddr:     beIPv4(10, 100, 0, 42),
			Daddr:     beIPv4(1, 1, 1, 1),
			Sport:     51000,
			Dport:     443,
			Proto:     6,
			Packets:   12,
			Bytes:     8456,
			RxPackets: 9,
			RxBytes:   12_004,
			FirstNs:   1_000_000_000,
			LastNs:    3_000_000_000, // 2s old
		},
		{ // unmanaged veth 99 -> dropped
			Ifindex: 99,
			Saddr:   beIPv4(10, 100, 0, 99),
			Daddr:   beIPv4(8, 8, 8, 8),
			Proto:   17,
			Packets: 1,
			Bytes:   60,
		},
	}
	attached := map[int]string{59: "web-container"}

	out := flowsToEBPF(records, attached, now)
	if len(out) != 1 {
		t.Fatalf("flowsToEBPF returned %d flows, want 1 (unmanaged veth dropped)", len(out))
	}
	f := out[0]
	if f.ContainerName != "web-container" {
		t.Errorf("ContainerName = %q, want web-container", f.ContainerName)
	}
	if f.SrcIP != "10.100.0.42" || f.ContainerIP != "10.100.0.42" {
		t.Errorf("SrcIP/ContainerIP = %s/%s, want 10.100.0.42", f.SrcIP, f.ContainerIP)
	}
	if f.DstIP != "1.1.1.1" || f.DstPort != 443 || f.SrcPort != 51000 {
		t.Errorf("unexpected ports/dst: src:%d dst:%s:%d", f.SrcPort, f.DstIP, f.DstPort)
	}
	if f.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want tcp", f.Protocol)
	}
	if f.Bytes != 8456 || f.Packets != 12 {
		t.Errorf("Bytes/Packets = %d/%d, want 8456/12", f.Bytes, f.Packets)
	}
	if f.RxBytes != 12_004 || f.RxPackets != 9 {
		t.Errorf("RxBytes/RxPackets = %d/%d, want 12004/9 (#631 reply direction)", f.RxBytes, f.RxPackets)
	}
	if !f.Last.Equal(now) {
		t.Errorf("Last = %v, want %v", f.Last, now)
	}
	if want := now.Add(-2 * time.Second); !f.First.Equal(want) {
		t.Errorf("First = %v, want %v (now - 2s duration)", f.First, want)
	}
}

func TestProtoName(t *testing.T) {
	for proto, want := range map[uint8]string{1: "icmp", 6: "tcp", 17: "udp", 47: ""} {
		if got := protoName(proto); got != want {
			t.Errorf("protoName(%d) = %q, want %q", proto, got, want)
		}
	}
}

// TestSplitIdleFlows covers the #632 idle reaper's partition: a flow whose last
// packet is older than the timeout is reaped, a recent one stays active, and a
// failed clock read (nowNs == 0) reaps nothing rather than sweeping live flows.
func TestSplitIdleFlows(t *testing.T) {
	const nowNs = uint64(100_000_000_000) // 100s on the monotonic clock
	idleTimeout := 2 * time.Second
	records := []netbpf.FlowRecord{
		{Sport: 1, LastNs: nowNs - uint64(5*time.Second)}, // idle: 5s > 2s
		{Sport: 2, LastNs: nowNs - uint64(1*time.Second)}, // active: 1s < 2s
		{Sport: 3, LastNs: nowNs},                         // active: just now
		{Sport: 4, LastNs: nowNs + uint64(time.Second)},   // future stamp (skew) -> active
	}

	active, idle := splitIdleFlows(records, nowNs, idleTimeout)

	if len(idle) != 1 || idle[0].Sport != 1 {
		t.Fatalf("idle = %+v, want exactly the sport=1 flow", idle)
	}
	if len(active) != 3 {
		t.Fatalf("active = %d flows, want 3", len(active))
	}

	// Clock read failed (nowNs == 0): nothing is idle.
	active0, idle0 := splitIdleFlows(records, 0, idleTimeout)
	if len(idle0) != 0 || len(active0) != len(records) {
		t.Fatalf("with nowNs=0 want no reaping; got active=%d idle=%d", len(active0), len(idle0))
	}
}
