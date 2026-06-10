package netbpf

import (
	"encoding/binary"
	"testing"
)

// encodeFlowKey / encodeFlowStat mirror the C `struct flow_key` / `struct
// flow_stat` wire layout, so the round-trip test pins the byte offsets the
// loader's Flows() decode relies on.
func encodeFlowKey(r FlowRecord) []byte {
	b := make([]byte, flowKeySize)
	binary.NativeEndian.PutUint32(b[0:4], r.Ifindex)
	binary.NativeEndian.PutUint32(b[4:8], r.Saddr)
	binary.NativeEndian.PutUint32(b[8:12], r.Daddr)
	binary.NativeEndian.PutUint16(b[12:14], r.Sport)
	binary.NativeEndian.PutUint16(b[14:16], r.Dport)
	b[16] = r.Proto
	return b
}

func encodeFlowStat(r FlowRecord) []byte {
	b := make([]byte, flowStatSize)
	binary.NativeEndian.PutUint64(b[0:8], r.Packets)
	binary.NativeEndian.PutUint64(b[8:16], r.Bytes)
	binary.NativeEndian.PutUint64(b[16:24], r.FirstNs)
	binary.NativeEndian.PutUint64(b[24:32], r.LastNs)
	return b
}

func TestDecodeFlow_RoundTrip(t *testing.T) {
	// 10.100.0.42:51000 -> 1.1.1.1:443, TCP, addresses in network byte order.
	want := FlowRecord{
		Ifindex: 59,
		Saddr:   binary.NativeEndian.Uint32([]byte{10, 100, 0, 42}),
		Daddr:   binary.NativeEndian.Uint32([]byte{1, 1, 1, 1}),
		Sport:   51000,
		Dport:   443,
		Proto:   6,
		Packets: 12,
		Bytes:   8456,
		FirstNs: 1_000_000_000,
		LastNs:  3_500_000_000,
	}

	var got FlowRecord
	if err := decodeFlowKey(encodeFlowKey(want), &got); err != nil {
		t.Fatalf("decodeFlowKey: %v", err)
	}
	if err := decodeFlowStat(encodeFlowStat(want), &got); err != nil {
		t.Fatalf("decodeFlowStat: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
	if got.Src().String() != "10.100.0.42" {
		t.Errorf("Src() = %s, want 10.100.0.42", got.Src())
	}
	if got.Dst().String() != "1.1.1.1" {
		t.Errorf("Dst() = %s, want 1.1.1.1", got.Dst())
	}
}

func TestDecodeFlow_ShortSamples(t *testing.T) {
	var r FlowRecord
	if err := decodeFlowKey([]byte{1, 2, 3}, &r); err == nil {
		t.Error("expected error for short flow key")
	}
	if err := decodeFlowStat([]byte{1, 2, 3}, &r); err == nil {
		t.Error("expected error for short flow stat")
	}
}
