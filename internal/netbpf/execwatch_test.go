package netbpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
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

// fakeRingReader yields a fixed sequence of ringbuf records then ErrClosed.
type fakeRingReader struct {
	recs []ringbuf.Record
	i    int
}

func (f *fakeRingReader) Read() (ringbuf.Record, error) {
	if f.i >= len(f.recs) {
		return ringbuf.Record{}, ringbuf.ErrClosed
	}
	r := f.recs[f.i]
	f.i++
	return r, nil
}

type captureExecSink struct{ events []ExecEvent }

func (c *captureExecSink) OnExecEvent(_ context.Context, ev ExecEvent) {
	c.events = append(c.events, ev)
}

func TestConsumeExecEvents(t *testing.T) {
	rd := &fakeRingReader{recs: []ringbuf.Record{
		{RawSample: rawExecEvent(1, 1, 0, 5, "a", "/a", []byte("a\x00"), false)},
		{RawSample: []byte{0xff, 0xfe}}, // malformed: reported, not delivered
		{RawSample: rawExecEvent(2, 1, 0, 6, "b", "/b", []byte("b\x00"), false)},
	}}
	sink := &captureExecSink{}
	var errs []error
	ConsumeExecEvents(context.Background(), rd, sink, func(err error) { errs = append(errs, err) })
	if len(sink.events) != 2 || sink.events[0].HostPID != 1 || sink.events[1].HostPID != 2 {
		t.Fatalf("delivered %+v, want pids 1 and 2", sink.events)
	}
	if len(errs) != 1 {
		t.Fatalf("errors = %v, want exactly the malformed-sample report", errs)
	}
}

func TestConsumeExecEvents_CtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rd := &fakeRingReader{recs: []ringbuf.Record{{RawSample: rawExecEvent(1, 1, 0, 5, "a", "/a", nil, false)}}}
	sink := &captureExecSink{}
	ConsumeExecEvents(ctx, rd, sink, nil)
	if len(sink.events) != 0 {
		t.Fatalf("delivered %d events after ctx cancel, want 0", len(sink.events))
	}
}

// A reader error other than ErrClosed ends the loop too (same contract as
// ConsumeDenyEvents: the caller owns restart policy), after reporting it.
func TestConsumeExecEvents_ReaderErrorStops(t *testing.T) {
	rd := &errRingReader{err: errors.New("boom")}
	var got error
	ConsumeExecEvents(context.Background(), rd, &captureExecSink{}, func(err error) { got = err })
	if got == nil || !strings.Contains(got.Error(), "boom") {
		t.Fatalf("reader error not reported: %v", got)
	}
}

type errRingReader struct{ err error }

func (e *errRingReader) Read() (ringbuf.Record, error) { return ringbuf.Record{}, e.err }

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
