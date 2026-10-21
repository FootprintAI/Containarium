package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/threatdetect"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// Host paths the watcher resolves a container's cgroup id from. Fields on the
// watcher so tests point them at a fake tree.
const (
	execProcRoot   = "/proc"
	execCgroupRoot = "/sys/fs/cgroup"

	// execReplayRing is how many recent events the watcher keeps in memory
	// for StreamExecEventsRequest.since. Events are deliberately NOT written
	// to the audit log (only matched findings are); this ring is the only
	// history and it is bounded.
	execReplayRing = 4096
	// execSubscriberBuffer is the per-stream channel depth. A subscriber
	// that lets it fill is dropped (its channel closed) rather than ever
	// blocking the ring consumer. Subscribe raises it to the replay's length
	// so a `--since … --follow` stream has room for the live events that
	// arrive while its replay is being sent.
	execSubscriberBuffer = 256

	execTelemetryOK               = "ok"
	execTelemetryNotStartedStatus = "unavailable (not started)"
	execTelemetryStoppedStatus    = "unavailable (stopped)"
)

// execTelemetryUnavailable renders a load/attach failure as the status
// string GetSentryStatus.exec_telemetry carries and the health loop keys on.
func execTelemetryUnavailable(err error) string { return "unavailable (" + err.Error() + ")" }

// execCgroupMap is what the watcher needs from the kernel object:
// *netbpf.ExecWatch satisfies it; tests use a fake.
type execCgroupMap interface {
	WatchCgroup(cgroupID uint64, index uint32) error
	UnwatchCgroup(cgroupID uint64) error
}

// execTarget is the container a watched cgroup id maps back to.
type execTarget struct {
	Container string
	TenantID  string
}

// ExecEventRecord is one decoded, attributed exec event — what the engine
// (as a threatdetect.ExecEvent), the replay ring and the stream subscribers
// see.
type ExecEventRecord struct {
	Container string
	TenantID  string
	At        time.Time
	Event     netbpf.ExecEvent
}

type execSubscriber struct {
	container string
	ch        chan ExecEventRecord
}

// ExecWatcher is the userspace half of the exec telemetry (#2637; design
// component 1): it keeps the kernel's watched_cgroups map in step with the
// running tenant containers, attributes each ring event to its container,
// hands it to the threat-detection engine and to a bounded fan-out for
// StreamExecEvents, and reports its own health as the `exec-telemetry`
// status line. It rides the NetworkPolicyEnforcer's 10 s reconcile (which
// already lists the containers with their init pids) and its lifecycle, but
// loads its own object: a failure here leaves the flow rules untouched.
type ExecWatcher struct {
	procRoot   string
	cgroupRoot string
	engine     func(threatdetect.ExecEvent) // nil = no engine consumer
	now        func() time.Time

	mu           sync.Mutex
	status       string
	maps         execCgroupMap // nil until Start loaded the object
	lost         func() uint64
	byCgroup     map[uint64]execTarget
	byName       map[string]uint64
	resolveFail  map[string]string // container → last logged resolve error, to log once
	nextIndex    uint32
	ring         []ExecEventRecord // replay ring, oldest at ringHead
	ringHead     int
	subs         map[int]*execSubscriber
	nextSub      int
	unattributed uint64
	subsDropped  uint64

	watch  *netbpf.ExecWatch
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewExecWatcher builds a watcher that hands attributed events to engine
// (nil when no rule consumes them). Start loads the kernel object.
func NewExecWatcher(engine func(threatdetect.ExecEvent)) *ExecWatcher {
	return &ExecWatcher{
		procRoot:    execProcRoot,
		cgroupRoot:  execCgroupRoot,
		engine:      engine,
		now:         time.Now,
		status:      execTelemetryNotStartedStatus,
		byCgroup:    make(map[uint64]execTarget),
		byName:      make(map[string]uint64),
		resolveFail: make(map[string]string),
		subs:        make(map[int]*execSubscriber),
	}
}

// Start loads the execwatch object from the same operator value the
// enforcer resolves (netbpf.ResolveExecWatch), attaches the tracepoint and
// starts the ring consumer. On any failure the status becomes
// `unavailable (<reason>)` and the error is returned; the caller logs and
// keeps the flow rules running.
func (w *ExecWatcher) Start(ctx context.Context, objValue string) error {
	watch, err := netbpf.ResolveExecWatch(objValue)
	if err != nil {
		w.setStatus(execTelemetryUnavailable(err))
		return err
	}
	if err := watch.Attach(); err != nil {
		_ = watch.Close()
		w.setStatus(execTelemetryUnavailable(err))
		return err
	}
	rd, err := watch.NewExecReader()
	if err != nil {
		_ = watch.Close()
		w.setStatus(execTelemetryUnavailable(err))
		return err
	}
	cctx, cancel := context.WithCancel(ctx)
	w.mu.Lock()
	w.watch = watch
	w.maps = watch
	w.lost = watch.Lost
	w.cancel = cancel
	w.status = execTelemetryOK
	w.mu.Unlock()

	w.wg.Add(1)
	go w.consume(cctx, rd)
	return nil
}

// execRingReader is the ring reader the consumer drains: *ringbuf.Reader in
// the daemon, a fake in tests. The consumer drains it in timed batches
// (netbpf.ExecDrainInterval, #2774), hence ReadInto, SetDeadline and
// AvailableBytes.
type execRingReader interface {
	ReadInto(rec *ringbuf.Record) error
	SetDeadline(t time.Time)
	AvailableBytes() int
	Close() error
}

// consume runs the ring consumer until ctx ends or the reader fails. A
// consumer that exits while the watcher is still meant to be running (a
// read error, not Stop) is a blind spot — the kernel keeps emitting into a
// ring nobody drains — so the status flips to `unavailable (ring consumer
// exited: …)`, which GetSentryStatus reports and the health loop raises,
// and every open stream is ended rather than left waiting forever.
func (w *ExecWatcher) consume(ctx context.Context, rd execRingReader) {
	defer w.wg.Done()
	// Close only after the loop has returned. The loop never blocks longer
	// than one drain tick (its reads have a deadline of now), so a cancelled
	// ctx ends it promptly, and closing concurrently would race the reader's
	// unlocked AvailableBytes (cilium/ebpf unmaps the ring in Close).
	defer func() { _ = rd.Close() }()
	var last error
	netbpf.ConsumeExecEvents(ctx, rd, w, func(err error) {
		log.Printf("[exec-telemetry] ring: %v", err)
		last = err
	})
	if ctx.Err() != nil {
		return // Stop: it owns the status
	}
	reason := errors.New("ring consumer exited")
	if last != nil {
		reason = fmt.Errorf("ring consumer exited: %w", last)
	}
	log.Printf("[exec-telemetry] %v; exec telemetry is unavailable until the daemon restarts", reason)
	w.mu.Lock()
	w.status = execTelemetryUnavailable(reason)
	w.closeSubscribersLocked()
	w.mu.Unlock()
}

// Stop ends the consumer, detaches the tracepoint and frees the object. It
// ends every open stream (closes its channel after the status has left
// "ok", so StreamExecEvents returns UNAVAILABLE rather than holding up the
// gRPC server's GracefulStop) and forgets the attribution tables, so a
// later Start re-registers every box in the new kernel map.
func (w *ExecWatcher) Stop() {
	w.mu.Lock()
	cancel, watch := w.cancel, w.watch
	w.cancel, w.watch, w.maps, w.lost = nil, nil, nil, nil
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	w.wg.Wait()
	if watch != nil {
		if err := watch.Close(); err != nil {
			log.Printf("[exec-telemetry] close: %v", err)
		}
	}
	w.mu.Lock()
	if watch != nil || w.status == execTelemetryOK {
		w.status = execTelemetryStoppedStatus
	}
	w.closeSubscribersLocked()
	w.byCgroup = make(map[uint64]execTarget)
	w.byName = make(map[string]uint64)
	w.resolveFail = make(map[string]string)
	w.mu.Unlock()
}

// closeSubscribersLocked ends every stream subscription. Callers hold w.mu
// and have already moved the status off "ok", which is how the stream
// handler tells this apart from a slow subscriber being dropped.
func (w *ExecWatcher) closeSubscribersLocked() {
	for id, s := range w.subs {
		close(s.ch)
		delete(w.subs, id)
	}
}

func (w *ExecWatcher) setStatus(s string) {
	w.mu.Lock()
	w.status = s
	w.mu.Unlock()
}

// Status is the GetSentryStatus.exec_telemetry string: "ok" or
// "unavailable (<reason>)".
func (w *ExecWatcher) Status() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

// Running reports whether the object is attached and events can flow.
func (w *ExecWatcher) Running() bool { return w.Status() == execTelemetryOK }

// Lost is the kernel's count of events dropped because the ring was full
// (GetSentryStatus.exec_events_lost); 0 before Start.
func (w *ExecWatcher) Lost() int64 {
	w.mu.Lock()
	fn := w.lost
	w.mu.Unlock()
	if fn == nil {
		return 0
	}
	v := fn()
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// Unattributed counts ring events whose cgroup id matched no registered
// container (a box that stopped between the exec and the decode, or a stale
// map entry); they are dropped, never guessed.
func (w *ExecWatcher) Unattributed() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.unattributed
}

// SubscribersDropped counts stream subscribers disconnected for not keeping up.
func (w *ExecWatcher) SubscribersDropped() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.subsDropped
}

func (w *ExecWatcher) lookup(cgroupID uint64) (execTarget, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	t, ok := w.byCgroup[cgroupID]
	return t, ok
}

func (w *ExecWatcher) watchedCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.byName)
}

// execDesired is one running tenant container the reconcile wants watched.
type execDesired struct {
	id     uint64
	tenant string
}

// Reconcile converges watched_cgroups with the running tenant containers:
// each running, non-core container with an init pid is resolved
// /proc/<pid>/cgroup → the container's root cgroup → its inode and
// upserted; a container whose id changed (restart: new init, new cgroup
// directory) has the old id removed; stopped or vanished containers are
// removed. Core-role containers (control plane, postgres, caddy, …) are
// platform infrastructure, not tenants, and are never registered — their
// execs stay invisible by design. Called from the enforcer's reconcile; a
// no-op before Start.
//
// The /proc reads and the map syscalls run OUTSIDE w.mu: OnExecEvent takes
// the same lock for every ring event, and a pass over many containers must
// not stall the consumer. The lock is held only to diff against and swap
// the attribution tables. Removals are applied before additions so a
// reused cgroup inode (kernfs ids recycle) can never have a stopped box's
// removal delete a just-started box's entry.
func (w *ExecWatcher) Reconcile(containers []incus.ContainerInfo) {
	w.mu.Lock()
	maps := w.maps
	w.mu.Unlock()
	if maps == nil {
		return
	}

	// Phase 1, unlocked: resolve the desired set.
	desired := make(map[string]execDesired, len(containers))
	failed := make(map[string]string)
	for _, c := range containers {
		if c.Role != "" || !strings.EqualFold(c.State, "running") || c.Pid <= 0 {
			continue
		}
		tenant := resolveTenant(c.Tenant, c.Labels[cloudOrgIDLabel], c.Name)
		if tenant == "" {
			continue
		}
		id, err := cgroupIDForPID(w.procRoot, w.cgroupRoot, c.Pid)
		if err != nil {
			failed[c.Name] = err.Error()
			continue
		}
		desired[c.Name] = execDesired{id: id, tenant: tenant}
	}

	// Phase 2, locked: diff. Removals take effect in the tables at once (a
	// stopped box must not be attributed a reused id); additions are staged
	// and committed after their map write succeeded.
	type change struct {
		name string
		id   uint64
		idx  uint32 // map value for an addition, reserved here
	}
	var toRemove, toAdd []change
	w.mu.Lock()
	for name, msg := range failed {
		if w.resolveFail[name] != msg {
			log.Printf("[exec-telemetry] %s: cannot resolve cgroup id: %s (execs not watched until it resolves)", name, msg)
			w.resolveFail[name] = msg
		}
	}
	for name := range w.resolveFail {
		if _, stillFailing := failed[name]; !stillFailing {
			delete(w.resolveFail, name)
		}
	}
	for name, cur := range w.byName {
		d, want := desired[name]
		if !want || d.id != cur {
			toRemove = append(toRemove, change{name: name, id: cur})
			delete(w.byName, name)
			delete(w.byCgroup, cur)
		}
	}
	for name, d := range desired {
		if cur, ok := w.byName[name]; ok && cur == d.id {
			if t := w.byCgroup[d.id]; t.TenantID != d.tenant {
				t.TenantID = d.tenant
				w.byCgroup[d.id] = t
			}
			continue
		}
		w.nextIndex++
		toAdd = append(toAdd, change{name: name, id: d.id, idx: w.nextIndex})
	}
	w.mu.Unlock()

	// Phase 3, unlocked: kernel map writes, removals first.
	for _, r := range toRemove {
		if err := maps.UnwatchCgroup(r.id); err != nil {
			log.Printf("[exec-telemetry] %s: unwatch cgroup %d: %v", r.name, r.id, err)
		}
	}
	var added []change
	for _, a := range toAdd {
		if err := maps.WatchCgroup(a.id, a.idx); err != nil {
			log.Printf("[exec-telemetry] %s: watch cgroup %d: %v", a.name, a.id, err)
			continue
		}
		added = append(added, a)
	}

	// Phase 4, locked: commit the additions. An exec in a just-watched
	// cgroup that lands between the map write and this commit is counted
	// unattributed rather than guessed.
	w.mu.Lock()
	for _, a := range added {
		d := desired[a.name]
		w.byName[a.name] = a.id
		w.byCgroup[a.id] = execTarget{Container: a.name, TenantID: d.tenant}
	}
	w.mu.Unlock()
}

// containerCgroupRoot maps a process's cgroup path (relative to the cgroup
// root) to the CONTAINER's root cgroup: the prefix through the Incus payload
// component, "lxc.payload.<name>". Inside a systemd box PID 1 moves itself
// to "<root>/init.scope", and every service and SSH session lives under
// "<root>/system.slice/…" or "<root>/user.slice/…" — siblings of init.scope,
// not descendants. The kernel program matches ANCESTORS of the exec'ing
// task, so the id registered must be the payload root, or nothing but
// init's own execs would ever be seen. A path with no payload component
// (a non-Incus runtime) is used as is.
func containerCgroupRoot(rel string) string {
	if root, ok := incusPayloadRoot(rel); ok {
		return root
	}
	return rel
}

// incusPayloadRoot returns the prefix of rel through its Incus payload
// component; ok is false when rel has none (a non-Incus runtime).
func incusPayloadRoot(rel string) (root string, ok bool) {
	parts := strings.Split(strings.Trim(rel, "/"), "/")
	for i, p := range parts {
		if strings.HasPrefix(p, "lxc.payload.") {
			return strings.Join(parts[:i+1], "/"), true
		}
	}
	return "", false
}

// cgroupIDForPID resolves a container's init pid to the cgroup v2 id the
// kernel program must match: the inode of <cgroupRoot>/<container root
// cgroup> (containerCgroupRoot of the path in /proc/<pid>/cgroup), which is
// what bpf_get_current_ancestor_cgroup_id reports for every task in the
// box. The path comes out of /proc (host-derived, not tenant-supplied) but
// is still a variable path resolved against a host directory, so it is
// contained with os.Root like pkg/core/incus's cpu.stat reader.
func cgroupIDForPID(procRoot, cgroupRoot string, pid int64) (uint64, error) {
	if pid <= 0 {
		return 0, errors.New("container not running (no init pid)")
	}
	// #nosec G304 -- procRoot is a constant (or a test fixture) and pid an
	// int64 Incus reported.
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.FormatInt(pid, 10), "cgroup"))
	if err != nil {
		return 0, err
	}
	rel := incus.CgroupV2PathFromProc(string(raw))
	if rel == "" {
		return 0, fmt.Errorf("pid %d: no cgroup v2 path in /proc/%d/cgroup", pid, pid)
	}
	rel = containerCgroupRoot(rel)
	root, err := os.OpenRoot(cgroupRoot)
	if err != nil {
		return 0, err
	}
	defer func() { _ = root.Close() }()
	st, err := root.Stat(rel)
	if err != nil {
		return 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat %s: no inode available", rel)
	}
	return sys.Ino, nil
}

// OnExecEvent implements netbpf.ExecEventSink: attribute the kernel record to
// its container, append it to the replay ring, fan it out to subscribers
// (never blocking: a full subscriber is dropped) and hand it to the engine.
// Runs on the ring consumer goroutine.
//
// It also reads the process's start time (#2765) here, as early as
// userspace sees the exec and before taking w.mu: the kill compares it with
// the pid's start time right before signalling, so a pid reused inside the
// same box is refused. A process that already exited (or whose stat cannot
// be read) gets no start time (0), and a kill for it is refused rather than
// aimed at whatever holds the pid by then. The residual window is exec →
// this read (one ring drain); closing it would need the kernel record to
// carry start_boottime.
func (w *ExecWatcher) OnExecEvent(_ context.Context, ev netbpf.ExecEvent) {
	start, _ := readProcStartTime(w.procRoot, ev.HostPID)
	w.mu.Lock()
	target, ok := w.byCgroup[ev.CgroupID]
	if !ok {
		w.unattributed++
		w.mu.Unlock()
		return
	}
	rec := ExecEventRecord{Container: target.Container, TenantID: target.TenantID, At: w.now(), Event: ev}
	w.appendRingLocked(rec)
	for id, s := range w.subs {
		if s.container != "" && s.container != rec.Container {
			continue
		}
		select {
		case s.ch <- rec:
		default:
			// Too slow: disconnect it rather than stall the kernel ring. The
			// stream handler sees the closed channel and tells the client.
			close(s.ch)
			delete(w.subs, id)
			w.subsDropped++
		}
	}
	engine := w.engine
	w.mu.Unlock()

	if engine != nil {
		engine(threatdetect.ExecEvent{
			Container:     rec.Container,
			TenantID:      rec.TenantID,
			At:            rec.At,
			PID:           ev.HostPID,
			StartTime:     start,
			PPID:          ev.PPID,
			UID:           ev.UID,
			Comm:          ev.Comm,
			Filename:      ev.Filename,
			Argv:          ev.Argv,
			ArgvTruncated: ev.ArgvTruncated,
		})
	}
}

func (w *ExecWatcher) appendRingLocked(rec ExecEventRecord) {
	if len(w.ring) < execReplayRing {
		w.ring = append(w.ring, rec)
		return
	}
	w.ring[w.ringHead] = rec
	w.ringHead = (w.ringHead + 1) % execReplayRing
}

// replayLocked returns the ring's events for container (all when empty)
// newer than since ago, oldest first. since <= 0 replays nothing.
func (w *ExecWatcher) replayLocked(container string, since time.Duration) []ExecEventRecord {
	if since <= 0 || len(w.ring) == 0 {
		return nil
	}
	cutoff := w.now().Add(-since)
	var out []ExecEventRecord
	n := len(w.ring)
	for i := 0; i < n; i++ {
		rec := w.ring[(w.ringHead+i)%n]
		if rec.At.Before(cutoff) {
			continue
		}
		if container != "" && rec.Container != container {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// Subscribe registers a stream subscriber: it returns the replay for the
// last `since` (taken under the same lock as the registration, so nothing is
// missed or duplicated at the seam), the live channel, and a cancel that
// unregisters. buffer <= 0 means execSubscriberBuffer; the buffer is never
// smaller than the replay, so live events arriving while a long replay is
// sent do not get a `--since … --follow` stream dropped before it reaches
// live mode. The channel is closed by the watcher when the subscriber falls
// behind, and on Stop or a consumer failure (status no longer "ok").
func (w *ExecWatcher) Subscribe(container string, since time.Duration, buffer int) (replay []ExecEventRecord, ch <-chan ExecEventRecord, cancel func()) {
	if buffer <= 0 {
		buffer = execSubscriberBuffer
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	replay = w.replayLocked(container, since)
	if len(replay) > buffer {
		buffer = len(replay)
	}
	id := w.nextSub
	w.nextSub++
	s := &execSubscriber{container: container, ch: make(chan ExecEventRecord, buffer)}
	w.subs[id] = s
	cancel = func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if cur, ok := w.subs[id]; ok && cur == s {
			delete(w.subs, id)
			close(s.ch)
		}
	}
	return replay, s.ch, cancel
}
