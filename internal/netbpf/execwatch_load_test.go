//go:build ebpf_load && linux

// Real-kernel coverage for the execwatch eBPF object (#2637), in the same
// lane as ebpf_load_test.go (.github/workflows/ebpf-load.yml, root, a BTF
// kernel). Everything else in this package tests the Go side against fakes;
// this file is where the compiled object is proven to pass the verifier with
// CO-RE against the running kernel, attach to sched/sched_process_exec, and
// emit exactly the events the design promises:
//
//   - an exec inside a cgroup registered in watched_cgroups → one event with
//     that cgroup id, comm, filename and argv;
//   - a host exec (cgroup not registered) → nothing;
//   - a 10k-exec burst with nobody draining the ring → a lost count, not a
//     crash, and the ring still readable afterwards;
//   - a paced 1,000 execs/s load for 60 s from a separate process, with and
//     without the program → the kernel + consumer CPU as a share of the
//     host, asserted under the < 1 % bar, with the batched ring wakeups
//     (#2774) compared against a wakeup per record.
//
// Cgroup placement uses clone3(CLONE_INTO_CGROUP) through exec.Cmd's
// UseCgroupFD, so the exec'ing child is in the test cgroup from its first
// instruction and the one event is unambiguous.
package netbpf

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const (
	ebpfLoadExecObjPath = "execwatch.bpf.o" // built next to netpolicy.bpf.o by `make build-bpf`
	ebpfLoadCgroupRoot  = "/sys/fs/cgroup"
)

// testCgroup is a throwaway cgroup v2 leaf under the root, with the inode the
// kernel reports as its cgroup id and an fd for CLONE_INTO_CGROUP.
type testCgroup struct {
	path string
	id   uint64
	fd   int
}

func newTestCgroup(t *testing.T, label string) *testCgroup {
	t.Helper()
	path := filepath.Join(ebpfLoadCgroupRoot, fmt.Sprintf("ebpfload-%s-%d", label, os.Getpid()))
	if err := os.Mkdir(path, 0o755); err != nil && !os.IsExist(err) {
		t.Fatalf("mkdir %s: %v (is cgroup v2 mounted at %s?)", path, err, ebpfLoadCgroupRoot)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat %s: no Stat_t", path)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	cg := &testCgroup{path: path, id: sys.Ino, fd: fd}
	t.Cleanup(func() {
		_ = syscall.Close(cg.fd)
		// Children have been waited for; a leaf with no processes removes
		// cleanly. Retry briefly in case the kernel is still reaping.
		for i := 0; i < 50; i++ {
			if err := os.Remove(cg.path); err == nil || os.IsNotExist(err) {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Logf("could not remove %s (left behind)", cg.path)
	})
	return cg
}

// run executes argv, inside cg when cg is non-nil, and waits for it.
func runExec(t *testing.T, cg *testCgroup, argv ...string) {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- fixed test argv
	if cg != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cg.fd}
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", argv, err, out)
	}
}

// collectingSink records events; the tests poll it.
type collectingSink struct {
	mu     sync.Mutex
	events []ExecEvent
}

func (s *collectingSink) OnExecEvent(_ context.Context, ev ExecEvent) {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
}

func (s *collectingSink) snapshot() []ExecEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ExecEvent(nil), s.events...)
}

// startConsumer drains w's ring into a sink until the test ends.
func startConsumer(t *testing.T, w *ExecWatch) *collectingSink {
	t.Helper()
	rd, err := w.NewExecReader()
	if err != nil {
		t.Fatalf("NewExecReader: %v", err)
	}
	sink := &collectingSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ConsumeExecEvents(ctx, rd, sink, func(err error) { t.Logf("consumer: %v", err) })
	}()
	t.Cleanup(func() {
		// ConsumeExecEvents returns within one tick of cancel. Close only
		// after it has: its AvailableBytes is unlocked and Close unmaps the
		// ring (#2812 review).
		cancel()
		<-done
		_ = rd.Close()
	})
	return sink
}

func loadAttached(t *testing.T) *ExecWatch {
	t.Helper()
	w, err := LoadExecWatch(ebpfLoadExecObjPath)
	if err != nil {
		t.Fatalf("LoadExecWatch(%q): %v", ebpfLoadExecObjPath, err)
	}
	t.Cleanup(func() { _ = w.Close() })
	if err := w.Attach(); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	return w
}

// TestExecWatch_RealObjectLoadsAndAttaches: the object passes this kernel's
// verifier (CO-RE relocations against the runner's BTF included), the
// tracepoint attaches, Attach is idempotent, and the maps are readable.
func TestExecWatch_RealObjectLoadsAndAttaches(t *testing.T) {
	w := loadAttached(t)
	if err := w.Attach(); err != nil {
		t.Fatalf("second Attach (idempotency): %v", err)
	}
	emitted, lost, err := w.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	t.Logf("fresh object: emitted=%d lost=%d", emitted, lost)
	if err := w.WatchCgroup(1, 1); err != nil {
		t.Fatalf("WatchCgroup: %v", err)
	}
	if err := w.UnwatchCgroup(1); err != nil {
		t.Fatalf("UnwatchCgroup: %v", err)
	}
	if err := w.UnwatchCgroup(1); err != nil {
		t.Fatalf("UnwatchCgroup (already gone): %v", err)
	}
}

// TestExecWatch_ShippedObjectSubmitsWithoutWakeup guards the kernel half of
// #2774, which no timing in the lane would catch (a timer consumer passes
// every overhead assertion even if the program woke it per record): the
// object as built ships exec_wakeup_per_record = 0, so the program submits
// with BPF_RB_NO_WAKEUP.
func TestExecWatch_ShippedObjectSubmitsWithoutWakeup(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(ebpfLoadExecObjPath)
	if err != nil {
		t.Fatalf("LoadCollectionSpec: %v", err)
	}
	v, ok := spec.Variables["exec_wakeup_per_record"]
	if !ok {
		t.Fatal("object has no exec_wakeup_per_record variable")
	}
	var perRecord uint8
	if err := v.Get(&perRecord); err != nil {
		t.Fatalf("read exec_wakeup_per_record: %v", err)
	}
	if perRecord != 0 {
		t.Fatalf("exec_wakeup_per_record defaults to %d in the shipped object, want 0 (BPF_RB_NO_WAKEUP)", perRecord)
	}
	if ms := spec.Maps[mapExecEvents]; ms == nil || ms.MaxEntries != execRingBytes {
		t.Fatalf("exec_events map spec = %+v, want a %d-byte ring", ms, execRingBytes)
	}
}

// TestExecWatch_WatchedCgroupYieldsExactlyOneEvent is the design's filtering
// contract on a real kernel: a host exec emits nothing; `sh -c true` inside
// a registered cgroup emits exactly one event carrying that cgroup id (the
// shell's own exec — `true` is a shell builtin, so no second exec).
func TestExecWatch_WatchedCgroupYieldsExactlyOneEvent(t *testing.T) {
	w := loadAttached(t)
	sink := startConsumer(t, w)
	cg := newTestCgroup(t, "one")

	// Host exec before anything is watched: nothing.
	runExec(t, nil, "sh", "-c", "true")
	time.Sleep(300 * time.Millisecond)
	if got := sink.snapshot(); len(got) != 0 {
		t.Fatalf("host exec emitted %d event(s) with nothing watched: %+v", len(got), got)
	}

	if err := w.WatchCgroup(cg.id, 1); err != nil {
		t.Fatalf("WatchCgroup(%d): %v", cg.id, err)
	}
	runExec(t, cg, "sh", "-c", "true")
	// Another host exec after the watch: still filtered.
	runExec(t, nil, "sh", "-c", "true")

	var got []ExecEvent
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got = sink.snapshot()
		if len(got) >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // let a spurious second event, if any, arrive
	got = sink.snapshot()
	if len(got) != 1 {
		t.Fatalf("watched exec yielded %d event(s), want exactly 1: %+v", len(got), got)
	}
	ev := got[0]
	t.Logf("event: pid=%d ppid=%d uid=%d cgroup=%d comm=%q filename=%q argv=%q truncated=%v",
		ev.HostPID, ev.PPID, ev.UID, ev.CgroupID, ev.Comm, ev.Filename, ev.Argv, ev.ArgvTruncated)
	if ev.CgroupID != cg.id {
		t.Errorf("cgroup_id = %d, want %d (inode of %s)", ev.CgroupID, cg.id, cg.path)
	}
	if ev.Comm != "sh" {
		t.Errorf("comm = %q, want sh", ev.Comm)
	}
	if !strings.HasSuffix(ev.Filename, "/sh") {
		t.Errorf("filename = %q, want a path ending in /sh", ev.Filename)
	}
	if strings.Join(ev.Argv, " ") != "sh -c true" {
		t.Errorf("argv = %q, want [sh -c true]", ev.Argv)
	}
	if ev.ArgvTruncated {
		t.Errorf("argv_truncated set for a 10-byte argv")
	}
	if ev.PPID != uint32(os.Getpid()) {
		t.Errorf("ppid = %d, want the test process %d", ev.PPID, os.Getpid())
	}
	if ev.UID != uint32(os.Getuid()) {
		t.Errorf("uid = %d, want %d", ev.UID, os.Getuid())
	}
	for _, a := range ev.Argv {
		if strings.HasPrefix(a, "PATH=") || strings.HasPrefix(a, "HOME=") {
			t.Errorf("argv carries an environment variable: %q", a)
		}
	}
}

// TestExecWatch_LongArgvIsCappedAndFlagged: an argv past 512 bytes arrives
// truncated with the flag set, and never grows into the environment.
func TestExecWatch_LongArgvIsCappedAndFlagged(t *testing.T) {
	w := loadAttached(t)
	sink := startConsumer(t, w)
	cg := newTestCgroup(t, "long")
	if err := w.WatchCgroup(cg.id, 1); err != nil {
		t.Fatalf("WatchCgroup: %v", err)
	}
	long := strings.Repeat("x", 700)
	runExec(t, cg, "sh", "-c", "true", "sh", long)
	var got []ExecEvent
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got = sink.snapshot(); len(got) >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	ev := got[0]
	if !ev.ArgvTruncated {
		t.Errorf("argv_truncated not set for a %d-byte argv", len("sh\x00-c\x00true\x00sh\x00")+len(long))
	}
	if n := len(ev.ArgvString()); n > execArgvLen {
		t.Errorf("argv string is %d bytes, cap is %d", n, execArgvLen)
	}
	if len(ev.Argv) < 4 || !strings.HasPrefix(ev.Argv[len(ev.Argv)-1], "xxxx") {
		t.Errorf("argv = %q, want the long argument's head as the last element", ev.Argv)
	}
}

// TestExecWatch_BurstReportsLostNotPanic: 10k execs in a watched cgroup with
// nobody draining the ring (4 MiB, ~5,090 records). The kernel must count the overflow in
// exec_stats[lost] (reported as exec_events_lost) and keep running; the
// ring must still be readable afterwards.
func TestExecWatch_BurstReportsLostNotPanic(t *testing.T) {
	w := loadAttached(t)
	cg := newTestCgroup(t, "burst")
	if err := w.WatchCgroup(cg.id, 1); err != nil {
		t.Fatalf("WatchCgroup: %v", err)
	}
	const n = 10000
	start := time.Now()
	runExec(t, cg, "sh", "-c", fmt.Sprintf("i=0; while [ $i -lt %d ]; do /bin/true; i=$((i+1)); done", n))
	elapsed := time.Since(start)

	emitted, lost, err := w.Stats()
	if err != nil {
		t.Fatalf("Stats after burst: %v", err)
	}
	ringBytes := w.EventsMap().MaxEntries()
	// Each record takes the 8-byte ringbuf header plus the 816-byte sample
	// (already 8-aligned), so an undrained ring holds exactly this many.
	capacity := uint64(ringBytes) / (execEventSize + 8)
	t.Logf("burst of %d execs in %s: emitted=%d lost=%d (ring %d bytes, %d-byte records, capacity %d)", n, elapsed.Round(time.Millisecond), emitted, lost, ringBytes, execEventSize, capacity)
	if ringBytes != execRingBytes {
		t.Errorf("exec_events ring is %d bytes, want %d (execRingBytes)", ringBytes, execRingBytes)
	}
	if emitted != capacity {
		t.Errorf("emitted = %d into an undrained %d-byte ring, want its capacity %d", emitted, ringBytes, capacity)
	}
	if emitted+lost < n {
		t.Fatalf("emitted+lost = %d, want >= %d (every watched exec is either emitted or counted lost)", emitted+lost, n)
	}
	if lost == 0 {
		t.Fatalf("lost = 0 after %d undrained execs into a %d-byte ring — the overflow counter is not working", n, ringBytes)
	}
	// The ring is still usable: a reader drains the records that did fit.
	rd, err := w.NewExecReader()
	if err != nil {
		t.Fatalf("NewExecReader after burst: %v", err)
	}
	defer func() { _ = rd.Close() }()
	rec, err := rd.Read()
	if err != nil {
		t.Fatalf("Read after burst: %v", err)
	}
	ev, err := ParseExecEvent(rec.RawSample)
	if err != nil {
		t.Fatalf("ParseExecEvent after burst: %v", err)
	}
	if ev.CgroupID != cg.id {
		t.Errorf("post-burst record cgroup_id = %d, want %d", ev.CgroupID, cg.id)
	}
}

// The overhead measurement (#2774) runs its exec load from a SEPARATE
// process, the shape the daemon sees in production: the exec'ing tasks live
// in a box, the consumer in an otherwise idle daemon. The first version of
// this test (#2637) generated the load from 16 goroutines in the test
// process itself and measured the kernel side as the RUSAGE_CHILDREN delta.
// That under-reported a per-event-wakeup design ~19x against a KVM guest:
// the consumer's wakeups landed in a process whose threads were already
// awake forking, so a wakeup cost little and drowned in the generator's own
// fork cost (subtracted as a noisy baseline); and the kernel-side cost of
// waking the consumer (irq_work, the IPI to an idle CPU) is not charged to
// the exec'ing child at all. Now the generator is this test binary re-exec'd
// with execLoadGenEnv set, the kernel side is the program's own run time
// (BPF_STATS_RUN_TIME), and the consumer side is this process's CPU — the
// same split the guest measurement used (bpftool run_time_ns + the daemon's
// /proc/<pid>/stat utime+stime).
const execLoadGenEnv = "EXECWATCH_LOADGEN" // "<rate>:<seconds>"

func init() {
	v := os.Getenv(execLoadGenEnv)
	if v == "" {
		return
	}
	var rate, secs int
	if _, err := fmt.Sscanf(v, "%d:%d", &rate, &secs); err != nil || rate <= 0 || secs <= 0 {
		fmt.Fprintf(os.Stderr, "loadgen: bad %s=%q\n", execLoadGenEnv, v)
		os.Exit(2)
	}
	execs, skipped := runExecLoadGen(rate, time.Duration(secs)*time.Second)
	fmt.Printf("loadgen execs=%d skipped=%d\n", execs, skipped)
	os.Exit(0)
}

// runExecLoadGen fork+execs /bin/true at a steady `rate` for d: four workers,
// each on its own fixed schedule offset by one period, so execs arrive
// evenly spaced (one every 1 ms at 1,000/s) rather than in bursts — the shape
// in which a per-event-wakeup consumer is woken once per event. A worker that
// falls more than one slot behind skips the missed slots instead of
// bursting to catch up; skipped counts them.
func runExecLoadGen(rate int, d time.Duration) (execs, skipped int64) {
	const workers = 4
	period := time.Second / time.Duration(rate)
	step := period * workers
	start := time.Now()
	end := start.Add(d)
	var n, skip atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			next := start.Add(time.Duration(w) * period)
			for next.Before(end) {
				if wait := time.Until(next); wait > 0 {
					time.Sleep(wait)
				}
				if exec.Command("/bin/true").Run() == nil {
					n.Add(1)
				}
				next = next.Add(step)
				if behind := time.Since(next); behind > step {
					missed := int64(behind / step)
					skip.Add(missed)
					next = next.Add(time.Duration(missed) * step)
				}
			}
		}(w)
	}
	wg.Wait()
	return n.Load(), skip.Load()
}

// procCPU is this process's CPU time and context switches (all threads).
type procCPU struct {
	cpu           time.Duration
	nvcsw, nivcsw int64
}

func selfUsage(t *testing.T) procCPU {
	t.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		t.Fatalf("getrusage: %v", err)
	}
	tv := func(v syscall.Timeval) time.Duration {
		return time.Duration(v.Sec)*time.Second + time.Duration(v.Usec)*time.Microsecond
	}
	return procCPU{cpu: tv(ru.Utime) + tv(ru.Stime), nvcsw: ru.Nvcsw, nivcsw: ru.Nivcsw}
}

// runLoadGenProcess runs the generator as a child process inside cg (so every
// /bin/true it forks is in the watched cgroup) and returns how many execs it
// completed. The caller samples its own CPU around this call.
func runLoadGenProcess(t *testing.T, cg *testCgroup, rate int, d time.Duration) uint64 {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(self, "-test.run=^$") // #nosec G204 -- re-exec of this test binary
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d:%d", execLoadGenEnv, rate, int(d/time.Second)))
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cg.fd}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("load generator: %v\n%s", err, out)
	}
	var execs, skipped uint64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "loadgen execs=%d skipped=%d", &execs, &skipped); err != nil {
		t.Fatalf("load generator output %q: %v", out, err)
	}
	if skipped > 0 {
		t.Logf("overhead: generator skipped %d slots (could not keep the pace)", skipped)
	}
	return execs
}

// daemonShapedSink does per event roughly what ExecWatcher.OnExecEvent does
// in the daemon (internal/server can't be imported here): take a mutex, look
// the cgroup up in a map, append to a bounded replay ring, build the engine's
// argv string. It also counts drains (ExecDrainObserver).
type daemonShapedSink struct {
	mu      sync.Mutex
	targets map[uint64]string
	ring    []ExecEvent
	head    int
	events  uint64
	argvLen int
	drains  uint64
	drained uint64
}

func newDaemonShapedSink(cgroupID uint64) *daemonShapedSink {
	return &daemonShapedSink{targets: map[uint64]string{cgroupID: "box"}, ring: make([]ExecEvent, 0, 4096)}
}

func (s *daemonShapedSink) OnExecEvent(_ context.Context, ev ExecEvent) {
	s.mu.Lock()
	if _, ok := s.targets[ev.CgroupID]; ok {
		if len(s.ring) < cap(s.ring) {
			s.ring = append(s.ring, ev)
		} else {
			s.ring[s.head] = ev
			s.head = (s.head + 1) % cap(s.ring)
		}
		s.events++
	}
	s.mu.Unlock()
	s.argvLen += len(ev.ArgvString())
}

func (s *daemonShapedSink) OnExecDrain(n int) {
	s.mu.Lock()
	s.drains++
	s.drained += uint64(max(n, 0))
	s.mu.Unlock()
}

func (s *daemonShapedSink) counts() (events, drains, drained uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events, s.drains, s.drained
}

// loadAttachedPerRecordWakeup is loadAttached with exec_wakeup_per_record
// set at load time (.rodata): the program submits with the default wakeup,
// as before #2774.
func loadAttachedPerRecordWakeup(t *testing.T) *ExecWatch {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec(ebpfLoadExecObjPath)
	if err != nil {
		t.Fatalf("LoadCollectionSpec: %v", err)
	}
	v, ok := spec.Variables["exec_wakeup_per_record"]
	if !ok {
		t.Fatalf("object has no exec_wakeup_per_record variable (rebuild execwatch.bpf.o)")
	}
	if err := v.Set(uint8(1)); err != nil {
		t.Fatalf("set exec_wakeup_per_record: %v", err)
	}
	w, err := newExecWatchFromSpec(spec)
	if err != nil {
		t.Fatalf("load with exec_wakeup_per_record=1: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	if err := w.Attach(); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	return w
}

// consumePerEvent is the pre-#2774 consumer: block in the reader (no
// deadline) and handle each record as its wakeup delivers it. Kept here only
// as the comparison point for the overhead measurement.
func consumePerEvent(ctx context.Context, rd *ringbuf.Reader, sink ExecEventSink) {
	var rec ringbuf.Record
	for ctx.Err() == nil {
		if err := rd.ReadInto(&rec); err != nil {
			return
		}
		if ev, err := ParseExecEvent(rec.RawSample); err == nil {
			sink.OnExecEvent(ctx, ev)
		}
	}
}

// overheadPhase is one measured window.
type overheadPhase struct {
	name           string
	execs          uint64
	selfCPU        time.Duration
	csw            int64 // voluntary + involuntary context switches of this process
	progRuntime    time.Duration
	progRuns       uint64
	emitted, lost  uint64
	events, drains uint64
	drained        uint64
	secs           float64
}

// measurePhase runs the generator for d with w attached (nil = baseline, no
// program) and a daemon-shaped consumer draining w's ring through
// ConsumeExecEvents — the exact loop the daemon's ExecWatcher runs — or,
// with perEvent, through the pre-#2774 blocking loop; then closes w.
func measurePhase(t *testing.T, name string, w *ExecWatch, perEvent bool, cg *testCgroup, rate int, d time.Duration) overheadPhase {
	t.Helper()
	ph := overheadPhase{name: name, secs: d.Seconds()}
	var sink *daemonShapedSink
	var stop func()
	if w != nil {
		if err := w.WatchCgroup(cg.id, 1); err != nil {
			t.Fatalf("WatchCgroup: %v", err)
		}
		rd, err := w.NewExecReader()
		if err != nil {
			t.Fatalf("NewExecReader: %v", err)
		}
		sink = newDaemonShapedSink(cg.id)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			if perEvent {
				consumePerEvent(ctx, rd, sink)
				return
			}
			ConsumeExecEvents(ctx, rd, sink, func(err error) { t.Logf("consumer: %v", err) })
		}()
		stop = func() {
			cancel()
			if perEvent {
				// The old loop blocks in the reader; only Close (which the
				// reader makes safe against its own locked ReadInto) ends it.
				_ = rd.Close()
				<-done
				return
			}
			// ConsumeExecEvents returns within one tick of cancel. Close only
			// after it has: its AvailableBytes is unlocked and Close unmaps
			// the ring.
			<-done
			_ = rd.Close()
		}
		time.Sleep(200 * time.Millisecond) // consumer parked in its first wait
	}
	var st0 *ebpf.ProgramStats
	if w != nil {
		var err error
		if st0, err = w.coll.Programs[progExecWatch].Stats(); err != nil {
			t.Fatalf("program stats: %v", err)
		}
	}
	u0 := selfUsage(t)
	ph.execs = runLoadGenProcess(t, cg, rate, d)
	u1 := selfUsage(t)
	ph.selfCPU = u1.cpu - u0.cpu
	ph.csw = (u1.nvcsw + u1.nivcsw) - (u0.nvcsw + u0.nivcsw)
	if w != nil {
		st1, err := w.coll.Programs[progExecWatch].Stats()
		if err != nil {
			t.Fatalf("program stats: %v", err)
		}
		ph.progRuntime = st1.Runtime - st0.Runtime
		ph.progRuns = st1.RunCount - st0.RunCount
		// Wait for the last batch: every record the kernel emitted delivered,
		// bounded generously so a stalled runner fails here, not flakily.
		if ph.emitted, ph.lost, err = w.Stats(); err != nil {
			t.Fatalf("Stats: %v", err)
		}
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if ev, _, _ := sink.counts(); ev >= ph.emitted {
				break
			}
		}
		stop()
		ph.events, ph.drains, ph.drained = sink.counts()
		// Detach now, so the next window runs with exactly one program.
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	return ph
}

func (ph overheadPhase) rate() float64 { return float64(ph.execs) / ph.secs }

// TestExecWatch_OverheadMeasurement measures the exec telemetry's cost at the
// acceptance load (1,000 execs/s for 60 s from a separate, steadily paced
// process; EBPF_LOAD_OVERHEAD_SECONDS overrides the duration) in three
// windows: a baseline with no program, the shipped batched path, and — for
// comparison — the per-event shape #2774 replaced (the object with
// exec_wakeup_per_record set, read by the old blocking consumer loop). Cost = the program's own run time
// (BPF_STATS_RUN_TIME) + this process's CPU above the baseline window (the
// consumer goroutine draining and decoding through ConsumeExecEvents into a
// daemon-shaped sink), reported per core and as a share of every CPU on the
// host. The bar (#2711, restated on #2774) is < 1 % of host CPU at 1,000
// execs/s; the lane asserts it on the batched path along with the batching
// itself (records per drain, context switches against the per-event shape),
// and that no watched exec goes unreported.
func TestExecWatch_OverheadMeasurement(t *testing.T) {
	d := 60 * time.Second
	if v := os.Getenv("EBPF_LOAD_OVERHEAD_SECONDS"); v != "" {
		var secs int
		if _, err := fmt.Sscanf(v, "%d", &secs); err == nil && secs > 0 {
			d = time.Duration(secs) * time.Second
		}
	}
	// The comparison window only has to show the gap, not meet a bar.
	dCmp := d / 3
	if dCmp < 10*time.Second {
		dCmp = 10 * time.Second
	}
	const rate = 1000
	nproc := runtime.NumCPU()
	cg := newTestCgroup(t, "load")

	statsOff, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		t.Fatalf("EnableStats(BPF_STATS_RUN_TIME): %v", err)
	}
	defer func() { _ = statsOff.Close() }()

	base := measurePhase(t, "baseline", nil, false, cg, rate, d)
	batched := measurePhase(t, "batched", loadAttached(t), false, cg, rate, d)
	perEvent := measurePhase(t, "per-event", loadAttachedPerRecordWakeup(t), true, cg, rate, dCmp)

	baseSelfPerSec := base.selfCPU.Seconds() / base.secs
	cost := func(ph overheadPhase) (kernelPct, consumerPct, totalPct, hostPct float64) {
		kernelPct = ph.progRuntime.Seconds() / ph.secs * 100
		consumerPct = (ph.selfCPU.Seconds()/ph.secs - baseSelfPerSec) * 100
		if consumerPct < 0 {
			consumerPct = 0
		}
		totalPct = kernelPct + consumerPct
		return kernelPct, consumerPct, totalPct, totalPct / float64(nproc)
	}
	t.Logf("overhead: nproc=%d target=%d execs/s drain-interval=%s", nproc, rate, ExecDrainInterval)
	t.Logf("overhead: baseline   %5.0fs execs=%d (%.0f/s) self-cpu=%s csw/s=%.0f",
		base.secs, base.execs, base.rate(), base.selfCPU.Round(time.Millisecond), float64(base.csw)/base.secs)
	for _, ph := range []overheadPhase{batched, perEvent} {
		k, c, tot, host := cost(ph)
		perRun := time.Duration(0)
		if ph.progRuns > 0 {
			perRun = time.Duration(float64(ph.progRuntime) / float64(ph.progRuns))
		}
		recsPerDrain := 0.0
		if ph.drains > 0 {
			recsPerDrain = float64(ph.drained) / float64(ph.drains)
		}
		t.Logf("overhead: %-10s %5.0fs execs=%d (%.0f/s) prog runs=%d run_time=%s (%s/run) self-cpu=%s csw/s=%.0f drains/s=%.1f records/drain=%.1f emitted=%d lost=%d delivered=%d",
			ph.name, ph.secs, ph.execs, ph.rate(), ph.progRuns, ph.progRuntime.Round(time.Microsecond), perRun, ph.selfCPU.Round(time.Millisecond),
			float64(ph.csw)/ph.secs, float64(ph.drains)/ph.secs, recsPerDrain, ph.emitted, ph.lost, ph.events)
		t.Logf("overhead: RESULT %-10s kernel=%.3f%% consumer=%.3f%% total=%.3f%% of one core = %.3f%% of host CPU (%d CPUs) at %.0f execs/s",
			ph.name, k, c, tot, host, nproc, ph.rate())
	}

	// No watched exec goes unreported: emitted or counted lost, and every
	// emitted record reaches the sink.
	for _, ph := range []overheadPhase{batched, perEvent} {
		if ph.emitted+ph.lost < ph.execs {
			t.Errorf("%s: emitted+lost=%d < execs=%d: watched execs went unreported without being counted lost", ph.name, ph.emitted+ph.lost, ph.execs)
		}
		if ph.lost != 0 {
			t.Errorf("%s: %d events lost at a steady %.0f execs/s (acceptance: exec_events_lost = 0)", ph.name, ph.lost, ph.rate())
		}
		// emitted is cumulative per object; each phase has its own object.
		if ph.events != ph.emitted {
			t.Errorf("%s: delivered %d events, kernel emitted %d", ph.name, ph.events, ph.emitted)
		}
	}
	if batched.rate() < rate/2 {
		t.Fatalf("generator reached only %.0f execs/s (want ~%d): the runner cannot carry the load, the numbers above do not answer the bar", batched.rate(), rate)
	}

	// The batching itself — structural, not timing-sensitive: at ~1,000
	// execs/s and a 50 ms drain, a drain carries tens of records, and the
	// consumer process switches context several times less than when every
	// record wakes it.
	if batched.drains > 0 {
		if per := float64(batched.drained) / float64(batched.drains); per < 10 {
			t.Errorf("batched: %.1f records per drain, want >= 10 at %.0f execs/s (is the consumer still draining per tick?)", per, batched.rate())
		}
	} else {
		t.Errorf("batched: no drains observed")
	}
	// Above the baseline window's own rate (Go's sysmon and the wait on the
	// generator switch too).
	baseCsw := float64(base.csw) / base.secs
	if b, p := float64(batched.csw)/batched.secs-baseCsw, float64(perEvent.csw)/perEvent.secs-baseCsw; b*3 > p {
		t.Errorf("batched: %.0f context switches/s above baseline vs %.0f/s with a wakeup per record; want at least 3x fewer", b, p)
	}

	// The bar: < 1 % of host CPU at ~1,000 execs/s, on the batched path.
	if _, _, _, host := cost(batched); host >= 1.0 {
		t.Errorf("batched: exec telemetry costs %.3f%% of host CPU at %.0f execs/s, bar is < 1%%", host, batched.rate())
	}
}
