package netbpf

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cilium/ebpf/perf"
)

func encodeDenyEvent(e DenyEvent) []byte {
	b := make([]byte, denyEventSizeV1)
	binary.NativeEndian.PutUint32(b[0:4], e.Ifindex)
	binary.NativeEndian.PutUint32(b[4:8], e.TenantID)
	binary.NativeEndian.PutUint32(b[8:12], e.Saddr)
	binary.NativeEndian.PutUint32(b[12:16], e.Daddr)
	binary.NativeEndian.PutUint16(b[16:18], e.Dport)
	b[18] = e.Proto
	return b
}

func TestParseDenyEvent_RoundTrip(t *testing.T) {
	// 10.100.0.155 -> 1.1.1.1, ICMP. Addresses in network byte order.
	want := DenyEvent{
		Ifindex:  59,
		TenantID: 1,
		Saddr:    binary.NativeEndian.Uint32([]byte{10, 100, 0, 155}),
		Daddr:    binary.NativeEndian.Uint32([]byte{1, 1, 1, 1}),
		Dport:    0,
		Proto:    1,
	}
	got, err := ParseDenyEvent(encodeDenyEvent(want))
	if err != nil {
		t.Fatalf("ParseDenyEvent: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
	if got.Src().String() != "10.100.0.155" {
		t.Errorf("Src() = %s, want 10.100.0.155", got.Src())
	}
	if got.Dst().String() != "1.1.1.1" {
		t.Errorf("Dst() = %s, want 1.1.1.1", got.Dst())
	}
}

func TestParseDenyEvent_ShortSample(t *testing.T) {
	if _, err := ParseDenyEvent([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short sample")
	}
}

func TestParseDenyEvent_PaddedSample(t *testing.T) {
	raw := append(encodeDenyEvent(DenyEvent{TenantID: 7, Proto: 6}), 0, 0, 0, 0) // padded
	ev, err := ParseDenyEvent(raw)
	if err != nil {
		t.Fatalf("ParseDenyEvent (padded): %v", err)
	}
	if ev.TenantID != 7 || ev.Proto != 6 {
		t.Errorf("padded decode wrong: %+v", ev)
	}
}

// fakeReader yields a fixed sequence of perf records then an error to stop the loop.
type fakeReader struct {
	recs []perf.Record
	i    int
}

func (f *fakeReader) Read() (perf.Record, error) {
	if f.i >= len(f.recs) {
		return perf.Record{}, errors.New("closed")
	}
	r := f.recs[f.i]
	f.i++
	return r, nil
}

type captureSink struct{ events []DenyEvent }

func (c *captureSink) OnDenyEvent(_ context.Context, ev DenyEvent) {
	c.events = append(c.events, ev)
}

func TestConsumeDenyEvents(t *testing.T) {
	e1 := DenyEvent{TenantID: 1, Proto: 1}
	e2 := DenyEvent{TenantID: 2, Proto: 6}
	rd := &fakeReader{recs: []perf.Record{
		{RawSample: encodeDenyEvent(e1)},
		{LostSamples: 3},          // should be reported, not delivered
		{RawSample: []byte{0xff}}, // malformed: reported, not delivered
		{RawSample: encodeDenyEvent(e2)},
	}}
	sink := &captureSink{}
	var errCount int
	ConsumeDenyEvents(context.Background(), rd, sink, func(error) { errCount++ })

	if len(sink.events) != 2 {
		t.Fatalf("expected 2 delivered events, got %d: %+v", len(sink.events), sink.events)
	}
	if sink.events[0].TenantID != 1 || sink.events[1].TenantID != 2 {
		t.Errorf("wrong events delivered: %+v", sink.events)
	}
	if errCount != 2 { // one lost-samples notice + one malformed
		t.Errorf("expected 2 error reports, got %d", errCount)
	}
}

func TestConsumeDenyEvents_CtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Even with records available, a cancelled ctx stops before delivering.
	rd := &fakeReader{recs: []perf.Record{{RawSample: encodeDenyEvent(DenyEvent{TenantID: 1})}}}
	sink := &captureSink{}
	ConsumeDenyEvents(ctx, rd, sink, nil)
	if len(sink.events) != 0 {
		t.Errorf("expected no events after ctx cancel, got %d", len(sink.events))
	}
}

// #2970 review: the program writes the verdict it actually applied into the
// byte that used to be the low half of pad2 (offset 22), so a split mode/
// egress_mode policy is labelled from the packet's real fate, not the
// tenant-wide mode. A sample without the byte decodes as DenyVerdictUnknown.
func TestParseDenyEvent_Verdict(t *testing.T) {
	full := func(verdict byte) []byte {
		b := make([]byte, 24)
		copy(b, encodeDenyEvent(DenyEvent{TenantID: 3, Proto: 6}))
		b[22] = verdict
		return b
	}
	tests := []struct {
		name string
		raw  []byte
		want uint8
	}{
		{"logged", full(1), DenyVerdictLogged},
		{"dropped", full(2), DenyVerdictDropped},
		{"older object wrote 0 in pad2", full(0), DenyVerdictUnknown},
		{"sample without the sig_id tail", encodeDenyEvent(DenyEvent{TenantID: 3}), DenyVerdictUnknown},
		{"sample ending at sig_id", full(2)[:22], DenyVerdictUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := ParseDenyEvent(tt.raw)
			if err != nil {
				t.Fatalf("ParseDenyEvent: %v", err)
			}
			if ev.Verdict != tt.want {
				t.Errorf("Verdict = %d, want %d", ev.Verdict, tt.want)
			}
		})
	}
}

// Dropped prefers the program-reported verdict and falls back to the
// caller's tenant-wide guess only when the sample did not carry one.
func TestDenyEvent_Dropped(t *testing.T) {
	tests := []struct {
		name     string
		verdict  uint8
		fallback bool
		want     bool
	}{
		{"logged overrides an enforced tenant (egress_mode=LOG_ONLY miss)", DenyVerdictLogged, true, false},
		{"dropped overrides a log_only tenant (egress_mode=ENFORCE miss)", DenyVerdictDropped, false, true},
		{"unknown falls back to enforced", DenyVerdictUnknown, true, true},
		{"unknown falls back to log_only", DenyVerdictUnknown, false, false},
		{"out-of-range byte falls back", 9, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (DenyEvent{Verdict: tt.verdict}).Dropped(tt.fallback); got != tt.want {
				t.Errorf("Dropped(%v) with verdict %d = %v, want %v", tt.fallback, tt.verdict, got, tt.want)
			}
		})
	}
}
