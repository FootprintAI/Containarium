package netbpf

import (
	"bytes"
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
	_        uint8  // pad, matches the C struct
}

// denyEventSize is the wire size of struct deny_event (4+4+4+4+2+1+1).
const denyEventSize = 20

// ParseDenyEvent decodes one perf-ring sample into a DenyEvent. It tolerates a
// sample longer than the struct (perf samples are padded) but rejects a short
// one.
func ParseDenyEvent(raw []byte) (DenyEvent, error) {
	if len(raw) < denyEventSize {
		return DenyEvent{}, fmt.Errorf("netbpf: deny event sample too short: %d < %d bytes", len(raw), denyEventSize)
	}
	var ev DenyEvent
	if err := binary.Read(bytes.NewReader(raw[:denyEventSize]), binary.NativeEndian, &ev); err != nil {
		return DenyEvent{}, fmt.Errorf("netbpf: decode deny event: %w", err)
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
