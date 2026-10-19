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
	// blocking the ring consumer.
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
	Index     uint32
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
	w.mu.Unlock()

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		go func() { <-cctx.Done(); _ = rd.Close() }() // unblock Read on shutdown
		netbpf.ConsumeExecEvents(cctx, rd, w, func(err error) {
			log.Printf("[exec-telemetry] ring: %v", err)
		})
	}()
	w.setStatus(execTelemetryOK)
	return nil
}

// Stop ends the consumer, detaches the tracepoint and frees the object.
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
		w.setStatus(execTelemetryStoppedStatus)
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

// Reconcile converges watched_cgroups with the running tenant containers:
// each running, non-core container with an init pid is resolved
// /proc/<pid>/cgroup → /sys/fs/cgroup/<path> inode and upserted; a container
// whose id changed (restart: new init, new cgroup directory) has the old id
// removed; stopped or vanished containers are removed. Core-role containers
// (control plane, postgres, caddy, …) are platform infrastructure, not
// tenants, and are never registered — their execs stay invisible by
// design. Called from the enforcer's reconcile; a no-op before Start.
func (w *ExecWatcher) Reconcile(containers []incus.ContainerInfo) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.maps == nil {
		return
	}
	desired := make(map[string]bool, len(containers))
	for _, c := range containers {
		if c.Role != "" || !strings.EqualFold(c.State, "running") || c.Pid <= 0 {
			continue
		}
		tenant := resolveTenant(c.Tenant, c.Labels[cloudOrgIDLabel], c.Name)
		if tenant == "" {
			continue
		}
		desired[c.Name] = true
		id, err := cgroupIDForPID(w.procRoot, w.cgroupRoot, c.Pid)
		if err != nil {
			if w.resolveFail[c.Name] != err.Error() {
				log.Printf("[exec-telemetry] %s: cannot resolve cgroup id: %v (execs not watched until it resolves)", c.Name, err)
				w.resolveFail[c.Name] = err.Error()
			}
			continue
		}
		delete(w.resolveFail, c.Name)
		if cur, ok := w.byName[c.Name]; ok {
			if cur == id {
				if t := w.byCgroup[id]; t.TenantID != tenant {
					t.TenantID = tenant
					w.byCgroup[id] = t
				}
				continue
			}
			// Restarted: a new init pid lives in a new cgroup directory.
			w.unwatchLocked(c.Name, cur)
		}
		w.nextIndex++
		if err := w.maps.WatchCgroup(id, w.nextIndex); err != nil {
			log.Printf("[exec-telemetry] %s: watch cgroup %d: %v", c.Name, id, err)
			continue
		}
		w.byName[c.Name] = id
		w.byCgroup[id] = execTarget{Container: c.Name, TenantID: tenant, Index: w.nextIndex}
	}
	for name, id := range w.byName {
		if !desired[name] {
			w.unwatchLocked(name, id)
		}
	}
	for name := range w.resolveFail {
		if !desired[name] {
			delete(w.resolveFail, name)
		}
	}
}

func (w *ExecWatcher) unwatchLocked(name string, id uint64) {
	if err := w.maps.UnwatchCgroup(id); err != nil {
		log.Printf("[exec-telemetry] %s: unwatch cgroup %d: %v", name, id, err)
	}
	delete(w.byName, name)
	delete(w.byCgroup, id)
}

// cgroupIDForPID resolves a host pid to its cgroup v2 id: the inode of
// <cgroupRoot>/<path from /proc/<pid>/cgroup>, which is what
// bpf_get_current_ancestor_cgroup_id reports. The path comes out of /proc
// (host-derived, not tenant-supplied) but is still a variable path resolved
// against a host directory, so it is contained with os.Root like
// pkg/core/incus's cpu.stat reader.
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
func (w *ExecWatcher) OnExecEvent(_ context.Context, ev netbpf.ExecEvent) {
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
			PPID:          ev.PPID,
			UID:           ev.UID,
			Comm:          ev.Comm,
			Filename:      ev.Filename,
			Argv:          ev.ArgvString(),
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
// unregisters. buffer <= 0 means execSubscriberBuffer. The channel is closed
// by the watcher when the subscriber falls behind.
func (w *ExecWatcher) Subscribe(container string, since time.Duration, buffer int) (replay []ExecEventRecord, ch <-chan ExecEventRecord, cancel func()) {
	if buffer <= 0 {
		buffer = execSubscriberBuffer
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	replay = w.replayLocked(container, since)
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
