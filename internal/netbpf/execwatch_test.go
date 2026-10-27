package netbpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
)

// execEventWire mirrors `struct exec_event` in
// experimental/ebpf-phaseA/execwatch.bpf.c field for field, so the Go
// compiler's own layout rules (natural alignment, same as clang's for the BPF
// target) reproduce the C struct and the test below can pin size and offsets
// with unsafe instead of hand-typed arithmetic.
type execEventWire struct {
	HostPID       uint32
	PPID          uint32
	UID           uint32
	_             uint32
	CgroupID      uint64
	Comm          [execCommLen]byte
	Filename      [execFilenameLen]byte
	Argv          [execArgvLen]byte
	ArgvTruncated uint8
	_             [7]uint8
}

// TestExecEventWireLayout pins the kernel ↔ daemon contract (#2637): the
// offsets ParseExecEvent decodes at must be the ones the C struct lays out.
// A field reordered or resized on either side fails here, not in production
// as garbage argv.
func TestExecEventWireLayout(t *testing.T) {
	var w execEventWire
	if got := unsafe.Sizeof(w); got != execEventSize {
		t.Fatalf("sizeof(exec_event) = %d, want %d", got, execEventSize)
	}
	offsets := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"host_pid", unsafe.Offsetof(w.HostPID), execOffHostPID},
		{"ppid", unsafe.Offsetof(w.PPID), execOffPPID},
		{"uid", unsafe.Offsetof(w.UID), execOffUID},
		{"cgroup_id", unsafe.Offsetof(w.CgroupID), execOffCgroupID},
		{"comm", unsafe.Offsetof(w.Comm), execOffComm},
		{"filename", unsafe.Offsetof(w.Filename), execOffFilename},
		{"argv", unsafe.Offsetof(w.Argv), execOffArgv},
		{"argv_truncated", unsafe.Offsetof(w.ArgvTruncated), execOffArgvTruncated},
	}
	for _, o := range offsets {
		if o.got != o.want {
			t.Errorf("offsetof(%s) = %d, want %d", o.name, o.got, o.want)
		}
	}
}

// rawExecEvent builds one wire sample. argv is the raw NUL-separated block
// exactly as the program copies it out of the task's memory.
func rawExecEvent(hostPID, ppid, uid uint32, cgroup uint64, comm, filename string, argv []byte, truncated bool) []byte {
	b := make([]byte, execEventSize)
	binary.NativeEndian.PutUint32(b[execOffHostPID:], hostPID)
	binary.NativeEndian.PutUint32(b[execOffPPID:], ppid)
	binary.NativeEndian.PutUint32(b[execOffUID:], uid)
	binary.NativeEndian.PutUint64(b[execOffCgroupID:], cgroup)
	copy(b[execOffComm:execOffComm+execCommLen], comm)
	copy(b[execOffFilename:execOffFilename+execFilenameLen], filename)
	copy(b[execOffArgv:execOffArgv+execArgvLen], argv)
	if truncated {
		b[execOffArgvTruncated] = 1
	}
	return b
}

func TestParseExecEvent(t *testing.T) {
	nul := func(parts ...string) []byte { return []byte(strings.Join(parts, "\x00") + "\x00") }
	longArg := strings.Repeat("A", execArgvLen) // fills the whole buffer: no terminating NUL survives
	tests := []struct {
		name    string
		raw     []byte
		want    ExecEvent
		wantErr bool
	}{
		{
			name: "well-formed",
			raw:  rawExecEvent(4242, 1, 1000, 0xabcdef, "xmrig", "/tmp/.x/xmrig", nul("./xmrig", "-o", "pool:3333"), false),
			want: ExecEvent{HostPID: 4242, PPID: 1, UID: 1000, CgroupID: 0xabcdef, Comm: "xmrig", Filename: "/tmp/.x/xmrig", Argv: []string{"./xmrig", "-o", "pool:3333"}},
		},
		{
			name: "padded sample decodes the same (newer object, longer record)",
			raw:  append(rawExecEvent(7, 1, 0, 9, "sh", "/bin/sh", nul("sh", "-c", "true"), false), 0, 0, 0, 0, 0, 0, 0, 0),
			want: ExecEvent{HostPID: 7, PPID: 1, UID: 0, CgroupID: 9, Comm: "sh", Filename: "/bin/sh", Argv: []string{"sh", "-c", "true"}},
		},
		{
			name: "truncated argv keeps the partial tail and sets the flag",
			raw:  rawExecEvent(8, 1, 0, 9, "node", "/usr/bin/node", []byte("node\x00--url=stratum+tcp://poo"), true),
			want: ExecEvent{HostPID: 8, PPID: 1, CgroupID: 9, Comm: "node", Filename: "/usr/bin/node", Argv: []string{"node", "--url=stratum+tcp://poo"}, ArgvTruncated: true},
		},
		{
			name: "oversize single argument fills the buffer with no NUL",
			raw:  rawExecEvent(9, 1, 0, 9, "a", "/a", []byte(longArg), true),
			want: ExecEvent{HostPID: 9, PPID: 1, CgroupID: 9, Comm: "a", Filename: "/a", Argv: []string{longArg}, ArgvTruncated: true},
		},
		{
			name: "comm and filename without a NUL terminator take the full field",
			raw:  rawExecEvent(10, 1, 0, 9, strings.Repeat("c", execCommLen), strings.Repeat("f", execFilenameLen), nul("c"), false),
			want: ExecEvent{HostPID: 10, PPID: 1, CgroupID: 9, Comm: strings.Repeat("c", execCommLen), Filename: strings.Repeat("f", execFilenameLen), Argv: []string{"c"}},
		},
		{
			name: "empty argv",
			raw:  rawExecEvent(11, 1, 0, 9, "x", "/x", nil, false),
			want: ExecEvent{HostPID: 11, PPID: 1, CgroupID: 9, Comm: "x", Filename: "/x"},
		},
		{
			name:    "short sample is rejected",
			raw:     bytes.Repeat([]byte{1}, execEventSize-10),
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseExecEvent(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseExecEvent = %+v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseExecEvent: %v", err)
			}
			if got.HostPID != tc.want.HostPID || got.PPID != tc.want.PPID || got.UID != tc.want.UID || got.CgroupID != tc.want.CgroupID ||
				got.Comm != tc.want.Comm || got.Filename != tc.want.Filename || got.ArgvTruncated != tc.want.ArgvTruncated {
				t.Errorf("scalar fields:\n got %+v\nwant %+v", got, tc.want)
			}
			if strings.Join(got.Argv, "|") != strings.Join(tc.want.Argv, "|") {
				t.Errorf("Argv = %q, want %q", got.Argv, tc.want.Argv)
			}
		})
	}
}

// TestExecEvent_ArgvNeverCarriesEnvironment is the acceptance criterion
// "argv ... never includes environment variables" at the decoder: even if a
// record's argv block were followed by environment-looking bytes past the
// 512-byte field, the decoder reads only the field.
func TestExecEvent_ArgvNeverCarriesEnvironment(t *testing.T) {
	raw := rawExecEvent(1, 1, 0, 9, "sh", "/bin/sh", []byte("sh\x00-c\x00true\x00"), false)
	raw = append(raw, []byte("HOME=/root\x00AWS_SECRET=hunter2\x00")...)
	ev, err := ParseExecEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ev.ArgvString(), "AWS_SECRET") || len(ev.Argv) != 3 {
		t.Fatalf("argv leaked bytes past the field: %q", ev.Argv)
	}
	if ev.ArgvString() != "sh -c true" {
		t.Fatalf("ArgvString = %q", ev.ArgvString())
	}
}

// fakeRingReader models *ringbuf.Reader for the timed drain: each round is
// what the ring holds at one tick. AvailableBytes reports the round's
// remaining records (an empty round reports 0, which ends it); ReadInto
// returns them one by one, then os.ErrDeadlineExceeded (ring empty, like the
// real reader with a deadline of now) and moves to the next round. After
// the last round it reports data and ErrClosed. Records are copied into the
// caller's reused buffer, as ReadInto does, so a decoder that kept a
// reference into it would see the next record's bytes.
type fakeRingReader struct {
	rounds    [][]ringbuf.Record
	round, i  int
	reads     int             // ReadInto calls
	taken     int             // ReadInto calls that returned a record (consumed from the ring)
	deadlines []time.Duration // deadline - now at each SetDeadline
}

// remaining is how many records are still in the ring (never consumed).
func (f *fakeRingReader) remaining() int {
	n := 0
	for r := f.round; r < len(f.rounds); r++ {
		n += len(f.rounds[r])
	}
	if f.round < len(f.rounds) {
		n -= f.i
	}
	return n
}

func (f *fakeRingReader) SetDeadline(t time.Time) {
	f.deadlines = append(f.deadlines, time.Until(t))
}

func (f *fakeRingReader) AvailableBytes() int {
	if f.round >= len(f.rounds) {
		return 1 // closed: let ReadInto report it
	}
	left := len(f.rounds[f.round]) - f.i
	if left == 0 {
		f.round++ // an idle tick
		f.i = 0
		return 0
	}
	return left * execEventSize
}

func (f *fakeRingReader) ReadInto(rec *ringbuf.Record) error {
	f.reads++
	if f.round >= len(f.rounds) {
		return ringbuf.ErrClosed
	}
	if f.i >= len(f.rounds[f.round]) {
		f.round++
		f.i = 0
		return os.ErrDeadlineExceeded
	}
	src := f.rounds[f.round][f.i]
	f.i++
	f.taken++
	rec.RawSample = append(rec.RawSample[:0], src.RawSample...)
	return nil
}

type captureExecSink struct {
	events  []ExecEvent
	drains  []int
	drainAt []time.Time
}

func (c *captureExecSink) OnExecEvent(_ context.Context, ev ExecEvent) {
	c.events = append(c.events, ev)
}

func (c *captureExecSink) OnExecDrain(n int) {
	c.drains = append(c.drains, n)
	c.drainAt = append(c.drainAt, time.Now())
}

func rec(pid uint32, comm string) ringbuf.Record {
	return ringbuf.Record{RawSample: rawExecEvent(pid, 1, 0, 5, comm, "/"+comm, []byte(comm+"\x00"), false)}
}

func recs(n int) []ringbuf.Record {
	out := make([]ringbuf.Record, n)
	for i := range out {
		out[i] = rec(uint32(i+1), "r") // #nosec G115 -- small test count
	}
	return out
}

func TestConsumeExecEvents(t *testing.T) {
	rd := &fakeRingReader{rounds: [][]ringbuf.Record{{
		rec(1, "a"),
		{RawSample: []byte{0xff, 0xfe}}, // malformed: reported, not delivered
		rec(2, "b"),
	}}}
	sink := &captureExecSink{}
	var errs []error
	ConsumeExecEventsEvery(context.Background(), rd, 5*time.Millisecond, sink, func(err error) { errs = append(errs, err) })
	if len(sink.events) != 2 || sink.events[0].HostPID != 1 || sink.events[1].HostPID != 2 {
		t.Fatalf("delivered %+v, want pids 1 and 2", sink.events)
	}
	if len(errs) != 1 {
		t.Fatalf("errors = %v, want exactly the malformed-sample report", errs)
	}
}

// #2774: the consumer drains in batches, one per tick: every record of the
// round delivered in order, the drain size reported once per tick (0 for an
// idle one), the reader's deadline set to now so it never sleeps in epoll,
// no read at all on an idle tick, and the reused buffer never aliased into a
// delivered event.
func TestConsumeExecEvents_DrainsInBatchesPerInterval(t *testing.T) {
	rd := &fakeRingReader{rounds: [][]ringbuf.Record{
		{rec(1, "a"), rec(2, "bb"), rec(3, "ccc")},
		{}, // idle tick
		{rec(4, "dddd"), rec(5, "e")},
	}}
	sink := &captureExecSink{}
	ConsumeExecEventsEvery(context.Background(), rd, 10*time.Millisecond, sink, nil)

	if want := []int{3, 0, 2}; !slices.Equal(sink.drains, want) {
		t.Fatalf("drain sizes = %v, want %v", sink.drains, want)
	}
	wantComm := []string{"a", "bb", "ccc", "dddd", "e"}
	if len(sink.events) != len(wantComm) {
		t.Fatalf("delivered %d events, want %d", len(sink.events), len(wantComm))
	}
	for i, ev := range sink.events {
		if ev.HostPID != uint32(i+1) || ev.Comm != wantComm[i] || ev.Filename != "/"+wantComm[i] || ev.ArgvString() != wantComm[i] { // #nosec G115 -- small index
			t.Errorf("event %d = pid %d comm %q filename %q argv %q, want pid %d comm %q", i, ev.HostPID, ev.Comm, ev.Filename, ev.ArgvString(), i+1, wantComm[i])
		}
	}
	// Reads: 3 records + end-of-ring, nothing on the idle tick, 2 + end, and
	// the final read that saw ErrClosed.
	if rd.reads != 8 {
		t.Errorf("ReadInto called %d times, want 8 (none on the idle tick)", rd.reads)
	}
	if len(rd.deadlines) != 3 {
		t.Fatalf("SetDeadline called %d times, want 3 (one per non-empty tick)", len(rd.deadlines))
	}
	for i, d := range rd.deadlines {
		if d > 0 {
			t.Errorf("deadline %d is %s in the future: the drain must not block in epoll", i, d)
		}
	}
}

func TestConsumeExecEvents_DefaultInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		rd := &fakeRingReader{rounds: [][]ringbuf.Record{{rec(1, "a")}, {rec(2, "b")}}}
		sink := &captureExecSink{}
		start := time.Now()
		ConsumeExecEventsEvery(context.Background(), rd, interval, sink, nil)
		if len(sink.drainAt) != 2 {
			t.Fatalf("interval %s: %d drains, want 2", interval, len(sink.drainAt))
		}
		// Both offsets are measured from start, not from each other: the
		// ticker fires on an absolute schedule, so a late first drain (a
		// loaded runner) shortens the gap to the second without the interval
		// being wrong.
		if first, second := sink.drainAt[0].Sub(start), sink.drainAt[1].Sub(start); first < ExecDrainInterval*8/10 || second < 2*ExecDrainInterval*8/10 {
			t.Fatalf("interval %s: drains at %s and %s after start; want about ExecDrainInterval (%s) and twice that", interval, first, second, ExecDrainInterval)
		}
	}
	// The latency bound the miner-signature rule's < 10 s budget relies on.
	if ExecDrainInterval <= 0 || ExecDrainInterval > time.Second {
		t.Fatalf("ExecDrainInterval = %s, want a positive sub-second bound", ExecDrainInterval)
	}
}

// A drain that hit the burst size is followed at once by another, not by
// the next tick; a smaller one waits for the tick.
func TestConsumeExecEvents_BurstRedrainsWithoutWaiting(t *testing.T) {
	const interval = 300 * time.Millisecond
	for _, tc := range []struct {
		first     int
		wantQuick bool
	}{{execBurstRecords, true}, {execBurstRecords - 1, false}} {
		rd := &fakeRingReader{rounds: [][]ringbuf.Record{recs(tc.first), {rec(9, "z")}}}
		sink := &captureExecSink{}
		ConsumeExecEventsEvery(context.Background(), rd, interval, sink, nil)
		if len(sink.drainAt) < 2 {
			t.Fatalf("first=%d: %d drains, want 2", tc.first, len(sink.drainAt))
		}
		gap := sink.drainAt[1].Sub(sink.drainAt[0])
		if quick := gap < interval/2; quick != tc.wantQuick {
			t.Errorf("first drain of %d records: next drain after %s, want quick=%v (burst size %d, interval %s)", tc.first, gap, tc.wantQuick, execBurstRecords, interval)
		}
	}
}

func TestConsumeExecEvents_CtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rd := &fakeRingReader{rounds: [][]ringbuf.Record{{rec(1, "a")}}}
	sink := &captureExecSink{}
	ConsumeExecEvents(ctx, rd, sink, nil)
	if len(sink.events) != 0 {
		t.Fatalf("delivered %d events after ctx cancel, want 0", len(sink.events))
	}
}

// Cancelling while the ring is idle returns promptly, without a Close.
func TestConsumeExecEvents_CtxCancelWhileIdle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	idle := &queueRingReader{closed: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ConsumeExecEventsEvery(ctx, idle, 10*time.Millisecond, &captureExecSink{}, nil)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumer did not return after ctx cancel on an idle ring")
	}
}

// Cancelling mid-batch stops at the next record rather than draining the
// rest of the round into a sink that is shutting down.
func TestConsumeExecEvents_CtxCancelMidBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	rd := &fakeRingReader{rounds: [][]ringbuf.Record{{rec(1, "a"), rec(2, "b"), rec(3, "c")}}}
	sink := &cancelAfterSink{n: 1, cancel: cancel}
	ConsumeExecEventsEvery(ctx, rd, 5*time.Millisecond, sink, nil)
	if sink.got != 1 {
		t.Fatalf("delivered %d events, want 1 (cancelled after the first)", sink.got)
	}
}

// A record ReadInto has returned is already consumed from the kernel ring
// (consumer_pos advanced): it must reach the sink even if ctx is cancelled
// by then, or it is neither delivered nor counted in exec_events_lost
// (#2812 review). With N records queued and a cancel landing after the k-th
// delivery, every record taken from the ring was delivered and the rest are
// still in it: taken == delivered and delivered + remaining == emitted.
func TestConsumeExecEvents_CtxCancelNeverDropsAConsumedRecord(t *testing.T) {
	const emitted = 8
	for cancelAfter := 1; cancelAfter <= emitted; cancelAfter++ {
		ctx, cancel := context.WithCancel(context.Background())
		rd := &fakeRingReader{rounds: [][]ringbuf.Record{recs(emitted)}}
		sink := &cancelAfterSink{n: cancelAfter, cancel: cancel}
		ConsumeExecEventsEvery(ctx, rd, 5*time.Millisecond, sink, nil)
		cancel()
		if sink.got != rd.taken {
			t.Errorf("cancel after %d: %d records taken from the ring, %d delivered: a consumed record was dropped", cancelAfter, rd.taken, sink.got)
		}
		if sink.got+rd.remaining() != emitted {
			t.Errorf("cancel after %d: delivered %d + remaining %d != emitted %d", cancelAfter, sink.got, rd.remaining(), emitted)
		}
		if sink.got != cancelAfter {
			t.Errorf("cancel after %d: delivered %d, want the drain to stop at the next record", cancelAfter, sink.got)
		}
	}
}

type cancelAfterSink struct {
	n, got int
	cancel func()
}

func (s *cancelAfterSink) OnExecEvent(context.Context, ExecEvent) {
	s.got++
	if s.got >= s.n {
		s.cancel()
	}
}

// A reader error other than ErrClosed ends the loop too (same contract as
// ConsumeDenyEvents: the caller owns restart policy), after reporting it.
func TestConsumeExecEvents_ReaderErrorStops(t *testing.T) {
	rd := &errRingReader{err: errors.New("boom")}
	var got error
	ConsumeExecEventsEvery(context.Background(), rd, 5*time.Millisecond, &captureExecSink{}, func(err error) { got = err })
	if got == nil || !strings.Contains(got.Error(), "boom") {
		t.Fatalf("reader error not reported: %v", got)
	}
}

type errRingReader struct{ err error }

func (e *errRingReader) ReadInto(*ringbuf.Record) error { return e.err }
func (e *errRingReader) SetDeadline(time.Time)          {}
func (e *errRingReader) AvailableBytes() int            { return 1 }

// queueRingReader is a concurrent fake: records pushed from another
// goroutine sit in the ring (no wakeup, as with BPF_RB_NO_WAKEUP) until the
// consumer's next tick drains them.
type queueRingReader struct {
	mu     sync.Mutex
	queue  [][]byte
	closed chan struct{}
}

func (r *queueRingReader) SetDeadline(time.Time) {}

func (r *queueRingReader) push(b []byte) {
	r.mu.Lock()
	r.queue = append(r.queue, b)
	r.mu.Unlock()
}

func (r *queueRingReader) AvailableBytes() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.queue) * execEventSize
}

func (r *queueRingReader) ReadInto(rec *ringbuf.Record) error {
	select {
	case <-r.closed:
		return ringbuf.ErrClosed
	default:
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.queue) == 0 {
		return os.ErrDeadlineExceeded
	}
	rec.RawSample = append(rec.RawSample[:0], r.queue[0]...)
	r.queue = r.queue[1:]
	return nil
}

type chanSink struct{ ch chan ExecEvent }

func (s chanSink) OnExecEvent(_ context.Context, ev ExecEvent) { s.ch <- ev }

func TestConsumeExecEvents_LatencyBoundedByInterval(t *testing.T) {
	const interval = 20 * time.Millisecond
	rd := &queueRingReader{closed: make(chan struct{})}
	sink := chanSink{ch: make(chan ExecEvent, 16)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ConsumeExecEventsEvery(context.Background(), rd, interval, sink, nil)
	}()
	defer func() { close(rd.closed); rd.push(nil); <-done }()

	for i := uint32(1); i <= 3; i++ {
		start := time.Now()
		rd.push(rec(i, "x").RawSample)
		select {
		case ev := <-sink.ch:
			if ev.HostPID != i {
				t.Fatalf("got pid %d, want %d", ev.HostPID, i)
			}
			// One interval plus scheduling slack; the bound that matters is
			// the < 10 s detection budget, so the slack is generous.
			if lat := time.Since(start); lat > interval+500*time.Millisecond {
				t.Fatalf("event %d delivered after %s, want about one %s interval", i, lat, interval)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("event %d never delivered", i)
		}
	}
}

// ResolveExecWatch mirrors Resolve: the embedded keyword with no embedded
// object fails clearly; a path is loaded as a file (the exec object is the
// netpolicy path's sibling execwatch.bpf.o, so one env var drives both).
func TestResolveExecWatch_EmbeddedAbsentErrors(t *testing.T) {
	if EmbeddedExecObject() != nil {
		// An embed_bpf build takes the load path instead; that path is the
		// lane's job. Not a t.Skip: the ebpf_load lane fails on any skip.
		t.Log("build embeds execwatch.bpf.o; the absent-object branch is not reachable here")
		return
	}
	// The empty value means embedded too (never a CWD-relative file).
	for _, mode := range []string{"", "  ", "embedded", "1", "TRUE", " on "} {
		_, err := ResolveExecWatch(mode)
		if err == nil {
			t.Fatalf("ResolveExecWatch(%q) = nil error, want a no-embedded-object error", mode)
		}
		if !strings.Contains(err.Error(), "no embedded execwatch BPF object") {
			t.Errorf("ResolveExecWatch(%q) error = %q", mode, err)
		}
	}
}

func TestExecObjectPathFor(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/opt/containarium/netpolicy.bpf.o", "/opt/containarium/execwatch.bpf.o"},
		{"/opt/containarium/execwatch.bpf.o", "/opt/containarium/execwatch.bpf.o"},
		{"netpolicy.bpf.o", "execwatch.bpf.o"},
		{"/some/dir/", "/some/dir/execwatch.bpf.o"},
		{"", ""},   // never "./execwatch.bpf.o" relative to the daemon's CWD
		{"  ", ""}, // whitespace is empty
	}
	for _, tc := range tests {
		if got := ExecObjectPathFor(tc.in); got != tc.want {
			t.Errorf("ExecObjectPathFor(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestResolveExecWatch_PathValueIsLoadedAsFile(t *testing.T) {
	_, err := ResolveExecWatch("/no/such/dir/netpolicy.bpf.o")
	if err == nil {
		t.Fatal("ResolveExecWatch(path) = nil error, want a stat error for a missing file")
	}
	if !strings.Contains(err.Error(), "/no/such/dir/execwatch.bpf.o") {
		t.Errorf("error should name the sibling exec object path: %v", err)
	}
}

// The C source is what `make build-bpf` compiles; pin the two #2774 kernel
// constants there so a change shows up in the plain unit suite, not only in
// the eBPF lane: the ring size the Go side assumes, and a shipped default of
// no per-record wakeup (BPF_RB_NO_WAKEUP on every submit).
func TestExecWatchSource_RingSizeAndNoWakeupDefault(t *testing.T) {
	src, err := os.ReadFile("../../experimental/ebpf-phaseA/execwatch.bpf.c")
	if err != nil {
		t.Fatalf("read execwatch.bpf.c: %v", err)
	}
	for _, want := range []string{
		"#define EXEC_RING_BYTES    (4 << 20)",
		"volatile const __u8 exec_wakeup_per_record = 0;",
		"__u64 wake = exec_wakeup_per_record ? 0 : BPF_RB_NO_WAKEUP;",
		"bpf_ringbuf_submit(ev, wake);",
	} {
		if !bytes.Contains(src, []byte(want)) {
			t.Errorf("execwatch.bpf.c no longer contains %q", want)
		}
	}
	if execRingBytes != 4<<20 {
		t.Errorf("execRingBytes = %d, want 4 MiB to match EXEC_RING_BYTES", execRingBytes)
	}
	if c := execRingBytes / (execEventSize + 8); c < 5000 {
		t.Errorf("ring capacity %d records, want >= 5000", c)
	}
}

// ExecObjectSource is what ResolveExecWatch loads and what the integrity
// self-measurement digests (#3120). It pins the empty-setting difference with
// Resolve (empty = embedded here, no program there) and that every alias
// Resolve accepts selects the embedded object too.
func TestExecObjectSource(t *testing.T) {
	for _, v := range []string{"", "  ", "embedded", "1", "TRUE", " on ", "yes"} {
		if emb, p := ExecObjectSource(v); !emb || p != "" {
			t.Errorf("ExecObjectSource(%q) = %v, %q; want embedded", v, emb, p)
		}
	}
	for _, v := range []string{"embedded", "1", "true", "yes", "on", "On"} {
		if !IsEmbeddedValue(v) {
			t.Errorf("IsEmbeddedValue(%q) = false", v)
		}
	}
	if IsEmbeddedValue("") {
		t.Error("IsEmbeddedValue(\"\") = true; the netpolicy resolver treats empty as no program")
	}
	emb, p := ExecObjectSource(" /opt/c/netpolicy.bpf.o ")
	if emb || p != "/opt/c/execwatch.bpf.o" {
		t.Errorf("path value = %v, %q", emb, p)
	}
}
