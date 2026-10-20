package netbpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Names in experimental/ebpf-phaseA/execwatch.bpf.c (#2637) — the second BPF
// object, kept apart from netpolicy.bpf.o so a verifier rejection or missing
// BTF here never takes flow enforcement down.
const (
	progExecWatch       = "execwatch"
	mapWatchedCgroups   = "watched_cgroups"
	mapExecEvents       = "exec_events"
	mapExecStats        = "exec_stats"
	execStatEmitted     = uint32(0)
	execStatLost        = uint32(1)
	execTracepointGroup = "sched"
	execTracepointName  = "sched_process_exec"

	// ExecObjectName is the exec object's file name; next to a netpolicy
	// object path it is the sibling ResolveExecWatch loads.
	ExecObjectName = "execwatch.bpf.o"
)

// Wire layout of `struct exec_event` — see the table in execwatch.bpf.c.
// TestExecEventWireLayout pins these against a Go mirror of the C struct.
const (
	execCommLen     = 16
	execFilenameLen = 256
	execArgvLen     = 512

	execOffHostPID       = 0
	execOffPPID          = 4
	execOffUID           = 8
	execOffCgroupID      = 16
	execOffComm          = 24
	execOffFilename      = 40
	execOffArgv          = 296
	execOffArgvTruncated = 808
	// execEventMin is the shortest sample that carries every field; the C
	// struct's tail padding brings sizeof to execEventSize. The parser accepts
	// anything from execEventMin up so a newer object that appends fields still
	// decodes on this daemon.
	execEventMin  = execOffArgvTruncated + 1
	execEventSize = 816

	// execRingBytes is EXEC_RING_BYTES in execwatch.bpf.c: 4 MiB, ~5,090
	// records of 816 bytes plus the 8-byte ring header (#2774 review). The
	// lane checks the compiled map against it.
	execRingBytes = 4 << 20
)

// ExecEvent is the decoded form of one `struct exec_event` the execwatch
// program emitted for a process exec inside a watched cgroup.
type ExecEvent struct {
	HostPID  uint32 // tgid in the host pid namespace
	PPID     uint32 // parent tgid, host pid namespace
	UID      uint32 // real uid of the exec'ing task
	CgroupID uint64 // the watched_cgroups key that matched — maps back to the container
	Comm     string // task comm after exec
	Filename string // resolved executable path from the tracepoint
	// Argv is the argument vector split on NUL. When ArgvTruncated is set the
	// block was capped at 512 bytes and the last element may be partial.
	Argv          []string
	ArgvTruncated bool
}

// ArgvString joins Argv with single spaces, for logs and the CLI line.
func (e ExecEvent) ArgvString() string { return strings.Join(e.Argv, " ") }

// ParseExecEvent decodes one ring-buffer sample into an ExecEvent. It
// tolerates a sample longer than the struct (a newer object appending fields)
// and rejects a short one. comm and filename are read up to their first NUL
// (or the whole field when none); argv is split on NUL within its 512-byte
// field only — nothing past the field is ever looked at, which is how the
// environment block that follows argv in the task's memory can never leak
// into an event even if the kernel side were wrong.
func ParseExecEvent(raw []byte) (ExecEvent, error) {
	if len(raw) < execEventMin {
		return ExecEvent{}, fmt.Errorf("netbpf: exec event sample too short: %d < %d bytes", len(raw), execEventMin)
	}
	b := binary.NativeEndian
	ev := ExecEvent{
		HostPID:       b.Uint32(raw[execOffHostPID:]),
		PPID:          b.Uint32(raw[execOffPPID:]),
		UID:           b.Uint32(raw[execOffUID:]),
		CgroupID:      b.Uint64(raw[execOffCgroupID:]),
		Comm:          cString(raw[execOffComm : execOffComm+execCommLen]),
		Filename:      cString(raw[execOffFilename : execOffFilename+execFilenameLen]),
		Argv:          splitArgv(raw[execOffArgv : execOffArgv+execArgvLen]),
		ArgvTruncated: raw[execOffArgvTruncated] != 0,
	}
	return ev, nil
}

// cString returns the bytes up to the first NUL, or all of them.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// splitArgv splits a NUL-separated argument block. The block normally ends
// with a NUL; a capped block may end mid-argument, which is kept as the last
// element. Trailing zero padding after the final NUL is ignored — which also
// means a trailing EMPTY argument (`cmd ""`) is indistinguishable from the
// padding and is dropped; harmless for name/argv matching, noted here so
// nobody counts on it.
func splitArgv(b []byte) []string {
	// Trim the zero fill after the last argument's terminator.
	end := len(b)
	for end > 0 && b[end-1] == 0 {
		end--
	}
	if end == 0 {
		return nil
	}
	// If the block ended in a NUL (the normal case), end now points past the
	// last argument's final byte; split what remains.
	parts := bytes.Split(b[:end], []byte{0})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, string(p))
	}
	return out
}

// ExecWatch owns a loaded execwatch collection and its tracepoint link.
// Linux-only at runtime, like Loader.
type ExecWatch struct {
	coll *ebpf.Collection
	link link.Link
}

// ExecObjectPathFor maps the operator's netpolicy object path to the exec
// object's: the sibling execwatch.bpf.o in the same directory, so the one
// CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT value drives both objects. A path
// that already names execwatch.bpf.o is returned as is; a directory gets the
// file appended. An empty path returns "" — it must never resolve to a file
// relative to the daemon's working directory.
func ExecObjectPathFor(objPath string) string {
	objPath = strings.TrimSpace(objPath)
	if objPath == "" {
		return ""
	}
	if strings.HasSuffix(objPath, "/") {
		return objPath + ExecObjectName
	}
	if filepath.Base(objPath) == ExecObjectName {
		return objPath
	}
	return filepath.Join(filepath.Dir(objPath), ExecObjectName)
}

// ResolveExecWatch loads the execwatch object from the same operator value
// Resolve takes: the embedded keyword selects the object compiled into this
// binary; any other value is a netpolicy object path whose sibling
// execwatch.bpf.o is loaded (ExecObjectPathFor). An empty value means
// embedded too (and fails when nothing is embedded) — never a file relative
// to the daemon's working directory.
func ResolveExecWatch(value string) (*ExecWatch, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "embedded", "1", "true", "yes", "on":
		obj := EmbeddedExecObject()
		if len(obj) == 0 {
			return nil, fmt.Errorf("netbpf: no embedded execwatch BPF object in this build " +
				"(release binaries bundle it; for a custom build run `make build-bpf` then build with -tags embed_bpf)")
		}
		return LoadExecWatchFromBytes(obj)
	default:
		return LoadExecWatch(ExecObjectPathFor(strings.TrimSpace(value)))
	}
}

// LoadExecWatch reads the compiled execwatch object at objPath and loads the
// collection (verifier runs here; nothing is attached yet).
func LoadExecWatch(objPath string) (*ExecWatch, error) {
	if _, err := os.Stat(objPath); err != nil {
		return nil, fmt.Errorf("netbpf: execwatch BPF object %q: %w", objPath, err)
	}
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("netbpf: execwatch: load spec: %w", err)
	}
	return newExecWatchFromSpec(spec)
}

// LoadExecWatchFromBytes loads the collection from an in-memory object (the
// embedded one).
func LoadExecWatchFromBytes(obj []byte) (*ExecWatch, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return nil, fmt.Errorf("netbpf: execwatch: load spec from embedded object: %w", err)
	}
	return newExecWatchFromSpec(spec)
}

func newExecWatchFromSpec(spec *ebpf.CollectionSpec) (*ExecWatch, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("netbpf: execwatch: RemoveMemlock: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// A missing kernel BTF or a CO-RE relocation failure surfaces here —
		// the reason the daemon reports as `exec-telemetry: unavailable (...)`.
		return nil, fmt.Errorf("netbpf: execwatch: load collection: %w", err)
	}
	for _, name := range []string{mapWatchedCgroups, mapExecEvents, mapExecStats} {
		if coll.Maps[name] == nil {
			coll.Close()
			return nil, fmt.Errorf("netbpf: execwatch BPF object missing map %q (rebuild execwatch.bpf.o?)", name)
		}
	}
	if coll.Programs[progExecWatch] == nil {
		coll.Close()
		return nil, fmt.Errorf("netbpf: execwatch BPF object missing program %q", progExecWatch)
	}
	return &ExecWatch{coll: coll}, nil
}

// Attach hooks the program onto the sched/sched_process_exec tracepoint.
// Idempotent. Nothing is emitted until WatchCgroup registers a cgroup.
func (w *ExecWatch) Attach() error {
	if w.link != nil {
		return nil
	}
	lnk, err := link.Tracepoint(execTracepointGroup, execTracepointName, w.coll.Programs[progExecWatch], nil)
	if err != nil {
		return fmt.Errorf("netbpf: execwatch: attach tracepoint %s/%s: %w", execTracepointGroup, execTracepointName, err)
	}
	w.link = lnk
	return nil
}

// WatchCgroup registers a cgroup id (the inode of /sys/fs/cgroup/<path>) so
// execs under it — at any depth — are emitted. index is opaque to the kernel.
// Upsert semantics: re-registering an id is a no-op apart from the index.
func (w *ExecWatch) WatchCgroup(cgroupID uint64, index uint32) error {
	if err := w.coll.Maps[mapWatchedCgroups].Update(&cgroupID, &index, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("netbpf: execwatch: update watched_cgroups[%d]: %w", cgroupID, err)
	}
	return nil
}

// UnwatchCgroup removes a cgroup id. A missing key is not an error (the
// desired state is already reached), like DeleteEgress.
func (w *ExecWatch) UnwatchCgroup(cgroupID uint64) error {
	if err := w.coll.Maps[mapWatchedCgroups].Delete(&cgroupID); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("netbpf: execwatch: delete watched_cgroups[%d]: %w", cgroupID, err)
	}
	return nil
}

// EventsMap exposes the ring buffer so the daemon opens a ringbuf.Reader
// over it (NewExecReader).
func (w *ExecWatch) EventsMap() *ebpf.Map { return w.coll.Maps[mapExecEvents] }

// NewExecReader opens a ring-buffer reader over exec_events.
func (w *ExecWatch) NewExecReader() (*ringbuf.Reader, error) {
	rd, err := ringbuf.NewReader(w.EventsMap())
	if err != nil {
		return nil, fmt.Errorf("netbpf: execwatch: ringbuf reader: %w", err)
	}
	return rd, nil
}

// Stats reads the (emitted, lost) counters. lost counts execs in a watched
// cgroup the program could not reserve ring space for — the number
// GetSentryStatus reports as exec_events_lost. Both are cumulative since
// load.
func (w *ExecWatch) Stats() (emitted, lost uint64, err error) {
	keyE, keyL := execStatEmitted, execStatLost
	if err = w.coll.Maps[mapExecStats].Lookup(&keyE, &emitted); err != nil {
		return 0, 0, fmt.Errorf("netbpf: execwatch: read exec_stats[emitted]: %w", err)
	}
	if err = w.coll.Maps[mapExecStats].Lookup(&keyL, &lost); err != nil {
		return 0, 0, fmt.Errorf("netbpf: execwatch: read exec_stats[lost]: %w", err)
	}
	return emitted, lost, nil
}

// Lost returns the lost-event counter alone; 0 when it cannot be read.
func (w *ExecWatch) Lost() uint64 {
	_, lost, err := w.Stats()
	if err != nil {
		return 0
	}
	return lost
}

// Close detaches the tracepoint and frees the collection.
func (w *ExecWatch) Close() error {
	var errs []error
	if w.link != nil {
		if err := w.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close tracepoint link: %w", err))
		}
		w.link = nil
	}
	if w.coll != nil {
		w.coll.Close()
		w.coll = nil
	}
	return errors.Join(errs...)
}

// ExecEventSink consumes decoded exec events. The daemon's ExecWatcher
// implements it (attributes the cgroup id to a container, then fans out).
type ExecEventSink interface {
	OnExecEvent(ctx context.Context, ev ExecEvent)
}

// ExecDrainInterval is how often the exec ring consumer drains the ring
// (#2774). The kernel side submits every record with BPF_RB_NO_WAKEUP, so
// nothing wakes the consumer per event; it wakes on a Go ticker instead and
// drains everything queued in one batch. The interval is the added
// detection latency bound for an exec event: 50 ms against the
// miner-signature rule's < 10 s budget. At 1,000 execs/s that turns ~1,000
// consumer wakeups a second into ~20, each draining ~50 records (~40 KiB of
// the 4 MiB ring).
//
// The wait is a Go timer, not a blocking epoll_wait with a timeout, on
// purpose: a goroutine that comes back from a long blocking syscall wakes
// the runtime's sysmon thread, which then polls at 20 µs for ~1 ms — ~60
// context switches per drain, measured in the eBPF lane as ~1,200/s and
// most of the consumer's CPU. A timer wakeup costs a couple; the drain
// itself is a zero-timeout epoll_wait, and it is skipped when the ring is
// empty.
const ExecDrainInterval = 50 * time.Millisecond

// execBurstRecords: a drain that delivered at least this many records (~5 %
// of the 4 MiB ring) is followed at once by another, without waiting for
// the next tick, until the backlog is small again. A sustained rate above
// ~5,000 execs/s is thus drained continuously, and only a host-wide burst of
// more than ~5,090 execs inside one interval (~100,000 execs/s) can overflow
// the ring — counted in exec_events_lost, never blocking an exec.
const execBurstRecords = 256

// ExecDrainObserver is an optional extension of ExecEventSink: when the sink
// implements it, OnExecDrain is called once per drain with the number of
// records the drain delivered (0 for a tick that found the ring empty). The
// lane's overhead test uses it to prove the batching; the daemon does not
// need it.
type ExecDrainObserver interface {
	OnExecDrain(records int)
}

// ringRecordReader is the subset of *ringbuf.Reader ConsumeExecEvents needs,
// so the loop is unit-testable with a fake. ReadInto reuses one Record (and
// its sample buffer) for every event; ParseExecEvent copies what it keeps.
type ringRecordReader interface {
	ReadInto(rec *ringbuf.Record) error
	SetDeadline(t time.Time)
	AvailableBytes() int
}

// ConsumeExecEvents reads samples from the exec ring until ctx ends or the
// reader is closed, decoding each and handing it to the sink — the ringbuf
// twin of ConsumeDenyEvents. It returns within one drain interval of ctx
// ending; Close the reader AFTER it returns, never concurrently: the loop
// calls the reader's AvailableBytes, which in cilium/ebpf takes no lock and
// reads the ring mapping Close unmaps (the daemon and the lane test both
// close after the loop). A malformed sample is
// reported via onError (nil to ignore) and skipped; a reader error other
// than ErrClosed is reported and ends the loop (the caller owns restart
// policy). Ring overflow is not visible here: the kernel counts it
// (ExecWatch.Stats), it never blocks or crashes the exec'ing process.
//
// The ring is drained in batches every ExecDrainInterval rather than on a
// wakeup per event (see ExecDrainInterval; ConsumeExecEventsEvery takes the
// interval explicitly).
func ConsumeExecEvents(ctx context.Context, rd ringRecordReader, sink ExecEventSink, onError func(error)) {
	ConsumeExecEventsEvery(ctx, rd, ExecDrainInterval, sink, onError)
}

// ConsumeExecEventsEvery is ConsumeExecEvents with an explicit drain
// interval (<= 0 means ExecDrainInterval). Each tick, when the ring holds
// data, the reader's deadline is set to now — so ReadInto never sleeps in
// epoll — and every queued record is read until the reader reports
// os.ErrDeadlineExceeded (ring empty), which ends the drain, not the loop.
func ConsumeExecEventsEvery(ctx context.Context, rd ringRecordReader, interval time.Duration, sink ExecEventSink, onError func(error)) {
	if interval <= 0 {
		interval = ExecDrainInterval
	}
	report := func(err error) {
		if onError != nil {
			onError(err)
		}
	}
	observer, _ := sink.(ExecDrainObserver)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	var rec ringbuf.Record
	burst := false
	for {
		if burst {
			if ctx.Err() != nil {
				return
			}
		} else {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
		n := 0
		if rd.AvailableBytes() > 0 {
			rd.SetDeadline(time.Now())
			for {
				// Check ctx before ReadInto, never after: a record ReadInto
				// has returned is already consumed from the kernel ring
				// (consumer_pos advanced), so returning here would drop it
				// without it ever being counted lost. A cancelled ctx stops
				// the drain at the next record, which stays in the ring.
				if ctx.Err() != nil {
					return
				}
				err := rd.ReadInto(&rec)
				if err == nil {
					ev, perr := ParseExecEvent(rec.RawSample)
					if perr != nil {
						report(perr)
						continue
					}
					n++
					sink.OnExecEvent(ctx, ev)
					continue
				}
				if errors.Is(err, os.ErrDeadlineExceeded) {
					break // ring drained
				}
				if !errors.Is(err, ringbuf.ErrClosed) {
					report(fmt.Errorf("netbpf: execwatch: ring read: %w", err))
				}
				return
			}
		}
		if observer != nil {
			observer.OnExecDrain(n)
		}
		burst = n >= execBurstRecords
	}
}
