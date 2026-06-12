package netbpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf/perf"
)

// DenyEvent is the decoded form of a `struct deny_event` emitted by the BPF
// program (experimental/ebpf-phaseA/netpolicy.bpf.c) for a would-deny flow. The
// binary layout must stay in lockstep with that C struct.
type DenyEvent struct {
	Ifindex  uint32
	TenantID uint32
	Saddr    uint32 // source IPv4, network byte order (as carried on the wire)
	Daddr    uint32 // destination IPv4, network byte order
	Dport    uint16 // host byte order (the program already ntoh'd it)
	Proto    uint8  // IP protocol number (1=ICMP, 6=TCP, 17=UDP)
	Reason   uint8  // why the flow was denied (DenyReason*); 0 on objects predating #660
	SigID    uint16 // matched signature id when Reason==SIGNATURE, else 0 (#661); 0 on objects predating it
}

// Deny reasons carried in DenyEvent.Reason — mirror the DENY_REASON_* #defines
// in netpolicy.bpf.c. An object built before #660 always emits 0
// (DenyReasonPolicy), which keeps the audit label as the generic policy deny.
const (
	DenyReasonPolicy       uint8 = 0 // failed the egress allow-list / intra-tenant / metadata check
	DenyReasonVirtualPatch uint8 = 1 // matched an explicit virtual-patch deny rule (#660)
	DenyReasonSignature    uint8 = 2 // matched a cleartext exploit signature (#661, Tier 2)
)

// denyEventSizeV1 is the wire size of struct deny_event through the Reason byte
// (#660). #661 appends u16 sig_id + u16 pad (→ 24 bytes); decoding stays tolerant
// of both so an object built before either feature still parses (missing tail → 0).
const denyEventSizeV1 = 20

// ParseDenyEvent decodes one perf-ring sample into a DenyEvent. It tolerates a
// sample longer than the struct (perf samples are padded, and newer objects
// carry the #661 sig_id tail) but rejects a short one. Decoded field-by-field so
// the optional tail is handled cleanly.
func ParseDenyEvent(raw []byte) (DenyEvent, error) {
	if len(raw) < denyEventSizeV1 {
		return DenyEvent{}, fmt.Errorf("netbpf: deny event sample too short: %d < %d bytes", len(raw), denyEventSizeV1)
	}
	b := binary.NativeEndian
	ev := DenyEvent{
		Ifindex:  b.Uint32(raw[0:4]),
		TenantID: b.Uint32(raw[4:8]),
		Saddr:    b.Uint32(raw[8:12]),
		Daddr:    b.Uint32(raw[12:16]),
		Dport:    b.Uint16(raw[16:18]),
		Proto:    raw[18],
		Reason:   raw[19],
	}
	if len(raw) >= 22 { // #661 sig_id tail present
		ev.SigID = b.Uint16(raw[20:22])
	}
	return ev, nil
}

// Src and Dst render the network-byte-order addresses as netip.Addr. The wire
// value is a __u32 holding the 4 IPv4 bytes in network order; NativeEndian.Put
// writes them back to the same byte sequence regardless of host endianness.
func (e DenyEvent) Src() netip.Addr { return ipFromBE(e.Saddr) }
func (e DenyEvent) Dst() netip.Addr { return ipFromBE(e.Daddr) }

func ipFromBE(v uint32) netip.Addr {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// DenyEventSink consumes decoded would-deny events. The daemon implements this
// to turn each event into an audit row; keeping it an interface keeps netbpf
// free of an internal/audit dependency.
type DenyEventSink interface {
	OnDenyEvent(ctx context.Context, ev DenyEvent)
}

// perfRecordReader is the subset of *perf.Reader that ConsumeDenyEvents needs,
// so the loop can be unit-tested with a fake reader.
type perfRecordReader interface {
	Read() (perf.Record, error)
}

// ConsumeDenyEvents reads would-deny samples from a perf ring until the reader
// returns an error (e.g. it is closed on shutdown) or ctx is cancelled, decoding
// each and handing it to the sink. Lost-sample notices and malformed samples are
// reported via the onError callback (nil to ignore) and do not stop the loop.
func ConsumeDenyEvents(ctx context.Context, rd perfRecordReader, sink DenyEventSink, onError func(error)) {
	report := func(err error) {
		if onError != nil {
			onError(err)
		}
	}
	for {
		if ctx.Err() != nil {
			return
		}
		rec, err := rd.Read()
		if err != nil {
			return // reader closed / unrecoverable
		}
		if rec.LostSamples > 0 {
			report(fmt.Errorf("netbpf: perf ring lost %d samples", rec.LostSamples))
			continue
		}
		ev, err := ParseDenyEvent(rec.RawSample)
		if err != nil {
			report(err)
			continue
		}
		sink.OnDenyEvent(ctx, ev)
	}
}
