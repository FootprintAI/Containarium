package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/threatdetect"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeTree builds a fake /proc + /sys/fs/cgroup under a temp dir: for each
// pid → cgroup path, a /proc/<pid>/cgroup file naming it and the cgroup
// directory itself. Returns the two roots and the inode of every cgroup
// directory on each path (the leaf and all its ancestors), keyed by path.
func fakeTree(t *testing.T, pids map[int64]string) (procRoot, cgroupRoot string, inode map[string]uint64) {
	t.Helper()
	base := t.TempDir()
	procRoot = filepath.Join(base, "proc")
	cgroupRoot = filepath.Join(base, "cgroup")
	inode = map[string]uint64{}
	for pid, cg := range pids {
		dir := filepath.Join(procRoot, fmt.Sprint(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// Real files carry a v1 line or two on hybrid hosts; the resolver
		// must pick the unified "0::" line.
		content := "1:name=systemd:/ignored\n0::/" + cg + "\n"
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		cgDir := filepath.Join(cgroupRoot, cg)
		if err := os.MkdirAll(cgDir, 0o755); err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(cg, "/")
		for i := range parts {
			prefix := strings.Join(parts[:i+1], "/")
			st, err := os.Stat(filepath.Join(cgroupRoot, prefix))
			if err != nil {
				t.Fatal(err)
			}
			inode[prefix] = st.Sys().(*syscall.Stat_t).Ino
		}
	}
	return procRoot, cgroupRoot, inode
}

// TestContainerCgroupRoot: the id registered for a box is its payload root,
// so an exec anywhere under it — init.scope, system.slice/ssh.service, a
// user session — has that id among its ancestors.
func TestContainerCgroupRoot(t *testing.T) {
	tests := []struct{ in, want string }{
		{"lxc.payload.box-a/init.scope", "lxc.payload.box-a"},
		{"lxc.payload.box-a/system.slice/ssh.service", "lxc.payload.box-a"},
		{"lxc.payload.box-a/user.slice/user-1000.slice/session-3.scope", "lxc.payload.box-a"},
		{"lxc.payload.box/.lxc", "lxc.payload.box"},
		{"lxc.payload.box-b", "lxc.payload.box-b"},
		{"/lxc.payload.box-b/", "lxc.payload.box-b"},
		{"user.slice/user-1000.slice/foo.service", "user.slice/user-1000.slice/foo.service"}, // no payload component: unchanged
	}
	for _, tc := range tests {
		if got := containerCgroupRoot(tc.in); got != tc.want {
			t.Errorf("containerCgroupRoot(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCgroupIDForPID(t *testing.T) {
	procRoot, cgroupRoot, ino := fakeTree(t, map[int64]string{
		4242: "lxc.payload.box-a/init.scope",           // systemd box: init sits in init.scope under the payload root
		4300: "lxc.payload.box-b",                      // init still at the payload root
		4400: "lxc.payload.box-c/.lxc",                 // liblxc's own cgroup under the root
		4500: "user.slice/user-1000.slice/foo.service", // no payload component: the leaf itself
		// An SSH session's shell in box-a, a SIBLING of init.scope: never read
		// by the resolver (only init pids are), but it must share the
		// registered ancestor — asserted below.
		4243: "lxc.payload.box-a/system.slice/ssh.service",
	})
	// A pid whose /proc entry has no unified line.
	if err := os.MkdirAll(filepath.Join(procRoot, "5000"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "5000", "cgroup"), []byte("1:cpu:/foo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A pid whose cgroup path names a directory that no longer exists.
	if err := os.MkdirAll(filepath.Join(procRoot, "5001"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "5001", "cgroup"), []byte("0::/gone\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A pid whose cgroup path tries to escape the cgroup root.
	if err := os.MkdirAll(filepath.Join(procRoot, "5002"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "5002", "cgroup"), []byte("0::/../proc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		pid     int64
		want    uint64
		wantErr string
	}{
		{name: "init in init.scope registers the payload root, not the leaf", pid: 4242, want: ino["lxc.payload.box-a"]},
		{name: "init at the payload root", pid: 4300, want: ino["lxc.payload.box-b"]},
		{name: "init under .lxc registers the payload root", pid: 4400, want: ino["lxc.payload.box-c"]},
		{name: "no payload component falls back to the leaf", pid: 4500, want: ino["user.slice/user-1000.slice/foo.service"]},
		{name: "an ssh session's cgroup resolves to the same registered root", pid: 4243, want: ino["lxc.payload.box-a"]},
		{name: "non-positive pid", pid: 0, wantErr: "not running"},
		{name: "missing /proc entry", pid: 9999, wantErr: "no such file"},
		{name: "no unified line", pid: 5000, wantErr: "no cgroup v2 path"},
		{name: "cgroup directory gone", pid: 5001, wantErr: "no such file"},
		{name: "path escaping the root is refused", pid: 5002, wantErr: "escapes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cgroupIDForPID(procRoot, cgroupRoot, tc.pid)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("cgroupIDForPID: %v", err)
			}
			if got != tc.want || got == 0 {
				t.Fatalf("id = %d, want %d", got, tc.want)
			}
		})
	}
	// The registered id must never be the leaf: an exec in
	// system.slice/ssh.service would otherwise have no watched ancestor.
	if ino["lxc.payload.box-a/init.scope"] == ino["lxc.payload.box-a"] {
		t.Fatal("fixture: leaf and root share an inode; the test cannot distinguish them")
	}
}

// fakeCgroupMap records WatchCgroup/UnwatchCgroup calls like the kernel map.
type fakeCgroupMap struct {
	mu      sync.Mutex
	entries map[uint64]uint32
	watched []uint64
	removed []uint64
	ops     []string // "watch <id>" / "unwatch <id>", in call order
	err     error
}

func newFakeCgroupMap() *fakeCgroupMap { return &fakeCgroupMap{entries: map[uint64]uint32{}} }

func (m *fakeCgroupMap) WatchCgroup(id uint64, idx uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.entries[id] = idx
	m.watched = append(m.watched, id)
	m.ops = append(m.ops, fmt.Sprintf("watch %d", id))
	return nil
}

func (m *fakeCgroupMap) UnwatchCgroup(id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, id)
	m.removed = append(m.removed, id)
	m.ops = append(m.ops, fmt.Sprintf("unwatch %d", id))
	return nil
}

func (m *fakeCgroupMap) ids() []uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]uint64, 0, len(m.entries))
	for id := range m.entries {
		out = append(out, id)
	}
	return out
}

func running(name string, pid int64, opts ...func(*incus.ContainerInfo)) incus.ContainerInfo {
	c := incus.ContainerInfo{Name: name, State: "Running", Pid: pid, Tenant: "t-" + name}
	for _, o := range opts {
		o(&c)
	}
	return c
}

func newTestWatcher(t *testing.T, procRoot, cgroupRoot string, m *fakeCgroupMap) *ExecWatcher {
	t.Helper()
	w := NewExecWatcher(nil)
	w.procRoot, w.cgroupRoot = procRoot, cgroupRoot
	w.maps = m
	w.setStatus(execTelemetryOK)
	return w
}

// TestWatchedCgroupsReconcile: started containers are added (by their cgroup
// inode), running ones kept, stopped ones removed, a restart (new init pid →
// new cgroup inode) swaps the entry, and the control plane, core-role
// containers and anything without a pid are never registered.
func TestWatchedCgroupsReconcile(t *testing.T) {
	procRoot, cgroupRoot, ino := fakeTree(t, map[int64]string{
		100: "lxc.payload.box-a",
		200: "lxc.payload.box-b",
		201: "lxc.payload.box-b.restarted", // box-b after a restart: new init pid, new cgroup dir
		300: "lxc.payload.core-postgres",
		400: "lxc.payload.cloud-cp",
	})
	m := newFakeCgroupMap()
	w := newTestWatcher(t, procRoot, cgroupRoot, m)

	w.Reconcile([]incus.ContainerInfo{
		running("box-a", 100),
		running("box-b", 200),
		running("core-postgres", 300, func(c *incus.ContainerInfo) { c.Role = incus.RolePostgres }),
		running("cloud-cp", 400, func(c *incus.ContainerInfo) { c.Role = incus.RoleControlPlane }),
		running("box-stopped", 0, func(c *incus.ContainerInfo) { c.State = "Stopped" }),
		running("box-nopid", 0),
	})
	want := map[uint64]string{ino["lxc.payload.box-a"]: "box-a", ino["lxc.payload.box-b"]: "box-b"}
	got := m.ids()
	if len(got) != 2 {
		t.Fatalf("watched after first reconcile = %v, want exactly box-a and box-b", got)
	}
	for _, id := range got {
		name, ok := w.lookup(id)
		if !ok || want[id] != name.Container {
			t.Errorf("id %d → %+v, want %q", id, name, want[id])
		}
		if name.TenantID != "t-"+want[id] {
			t.Errorf("id %d tenant = %q, want %q", id, name.TenantID, "t-"+want[id])
		}
	}

	// Steady state: same containers → no new writes, nothing removed.
	before := len(m.watched)
	w.Reconcile([]incus.ContainerInfo{running("box-a", 100), running("box-b", 200)})
	if len(m.watched) != before || len(m.removed) != 0 {
		t.Fatalf("steady reconcile wrote %d / removed %d entries, want 0 / 0", len(m.watched)-before, len(m.removed))
	}

	// box-b restarts (new pid 201 → new cgroup inode): old id removed, new added; box-a stops: removed.
	w.Reconcile([]incus.ContainerInfo{running("box-b", 201), running("box-a", 0, func(c *incus.ContainerInfo) { c.State = "Stopped" })})
	got = m.ids()
	if len(got) != 1 || got[0] != ino["lxc.payload.box-b.restarted"] {
		t.Fatalf("watched after restart/stop = %v, want only box-b's new id %d", got, ino["lxc.payload.box-b.restarted"])
	}
	if _, ok := w.lookup(ino["lxc.payload.box-a"]); ok {
		t.Error("box-a still attributable after it stopped")
	}
	if _, ok := w.lookup(ino["lxc.payload.box-b"]); ok {
		t.Error("box-b's old cgroup id still attributable after its restart")
	}
	if len(m.removed) != 2 {
		t.Errorf("removed = %v, want box-a's id and box-b's old id", m.removed)
	}

	// A container gone from the list entirely is removed too.
	w.Reconcile(nil)
	if ids := m.ids(); len(ids) != 0 {
		t.Fatalf("watched after an empty reconcile = %v, want none", ids)
	}
}

// Reconcile before Start (no kernel map yet) must not panic and must not
// remember anything.
func TestWatchedCgroupsReconcile_BeforeStartIsNoop(t *testing.T) {
	procRoot, cgroupRoot, _ := fakeTree(t, map[int64]string{100: "lxc.payload.box-a"})
	w := NewExecWatcher(nil)
	w.procRoot, w.cgroupRoot = procRoot, cgroupRoot
	w.Reconcile([]incus.ContainerInfo{running("box-a", 100)})
	if n := w.watchedCount(); n != 0 {
		t.Fatalf("watched = %d before Start, want 0", n)
	}
}

func kernelEvent(cg uint64, pid uint32, comm string, argv ...string) netbpf.ExecEvent {
	return netbpf.ExecEvent{HostPID: pid, PPID: 1, UID: 1000, CgroupID: cg, Comm: comm, Filename: "/usr/bin/" + comm, Argv: argv}
}

// TestExecWatcher_AttributesAndHandsToEngine: a decoded event for a watched
// cgroup reaches the engine hook as a threatdetect.ExecEvent with the
// container and tenant attached and argv joined; an event for an unknown
// cgroup is dropped and counted, never attributed to the wrong box.
func TestExecWatcher_AttributesAndHandsToEngine(t *testing.T) {
	procRoot, cgroupRoot, ino := fakeTree(t, map[int64]string{100: "lxc.payload.box-a"})
	m := newFakeCgroupMap()
	var got []threatdetect.ExecEvent
	w := newTestWatcher(t, procRoot, cgroupRoot, m)
	w.engine = func(ev threatdetect.ExecEvent) { got = append(got, ev) }
	w.now = func() time.Time { return time.Unix(1700000000, 0) }
	w.Reconcile([]incus.ContainerInfo{running("box-a", 100)})

	w.OnExecEvent(context.Background(), kernelEvent(ino["lxc.payload.box-a"], 4242, "xmrig", "./xmrig", "-o", "pool:3333"))
	w.OnExecEvent(context.Background(), kernelEvent(777777, 1, "sh", "sh")) // never registered

	if len(got) != 1 {
		t.Fatalf("engine got %d events, want 1: %+v", len(got), got)
	}
	ev := got[0]
	if ev.Container != "box-a" || ev.TenantID != "t-box-a" || ev.PID != 4242 || ev.PPID != 1 || ev.UID != 1000 ||
		ev.Comm != "xmrig" || ev.Filename != "/usr/bin/xmrig" || ev.ArgvString() != "./xmrig -o pool:3333" || !ev.At.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("engine event = %+v", ev)
	}
	if w.Unattributed() != 1 {
		t.Fatalf("unattributed = %d, want 1", w.Unattributed())
	}
}

// TestExecWatcher_KeepsArgumentBoundaries (#2768): the engine gets the real
// NUL-separated argument vector, so an argument holding spaces (a commit
// message) stays one argument for the argv matchers.
func TestExecWatcher_KeepsArgumentBoundaries(t *testing.T) {
	procRoot, cgroupRoot, ino := fakeTree(t, map[int64]string{100: "lxc.payload.box-a"})
	var got []threatdetect.ExecEvent
	w := newTestWatcher(t, procRoot, cgroupRoot, newFakeCgroupMap())
	w.engine = func(ev threatdetect.ExecEvent) { got = append(got, ev) }
	w.Reconcile([]incus.ContainerInfo{running("box-a", 100)})

	want := []string{"git", "commit", "-m", "document stratum+tcp:// pool format"}
	w.OnExecEvent(context.Background(), kernelEvent(ino["lxc.payload.box-a"], 4242, "git", want...))
	if len(got) != 1 || !slices.Equal(got[0].Argv, want) {
		t.Fatalf("engine events = %+v, want one with argv %q", got, want)
	}
}

// TestExecWatcher_StampsExecsWithBootClock (#2765): the watcher stamps
// every decoded exec with the boot clock and hands the stamp to the engine
// as StartTime, including an exec whose process already exited (the kill
// sorts that out against the live pid); a failed clock read gives no stamp
// (0), never a guessed one, and is counted. Nothing under /proc/<pid> is
// opened for it (procOpenTrap catches any open, through any code path).
func TestExecWatcher_StampsExecsWithBootClock(t *testing.T) {
	procRoot, cgroupRoot, ino := fakeTree(t, map[int64]string{100: "lxc.payload.box-a"})
	opens := procOpenTrap(t, procRoot, 4242, "my (miner)", 987654, procPerExecFiles...)
	m := newFakeCgroupMap()
	var got []threatdetect.ExecEvent
	w := newTestWatcher(t, procRoot, cgroupRoot, m)
	w.engine = func(ev threatdetect.ExecEvent) { got = append(got, ev) }
	clock := []threatdetect.ProcStartTicks{987654, 987660}
	var clockErr error
	w.bootTicks = func() (threatdetect.ProcStartTicks, error) {
		if clockErr != nil {
			return 0, clockErr
		}
		v := clock[0]
		clock = clock[1:]
		return v, nil
	}
	w.Reconcile([]incus.ContainerInfo{running("box-a", 100)})

	cg := ino["lxc.payload.box-a"]
	w.OnExecEvent(context.Background(), kernelEvent(cg, 4242, "xmrig", "./xmrig"))
	w.OnExecEvent(context.Background(), kernelEvent(cg, 5555, "sh", "sh")) // exited before decode
	clockErr = errors.New("clock_gettime failed")
	w.OnExecEvent(context.Background(), kernelEvent(cg, 6666, "sh", "sh"))

	if len(got) != 3 {
		t.Fatalf("engine got %d events, want 3", len(got))
	}
	if got[0].StartTime != 987654 || got[1].StartTime != 987660 {
		t.Fatalf("stamps = %d, %d; want 987654, 987660", got[0].StartTime, got[1].StartTime)
	}
	if got[2].StartTime != 0 {
		t.Fatalf("failed clock read: stamp = %d, want 0 (unknown)", got[2].StartTime)
	}
	if w.StampFailures() != 1 {
		t.Fatalf("stamp failures = %d, want 1", w.StampFailures())
	}
	if n := opens.Load(); n != 0 {
		t.Fatalf("decode opened files under /proc/4242 %d times, want 0", n)
	}
}

// TestExecWatcher_StampFailureIsCountedAndLogged: a failing boot clock is
// counted on every exec and logged the first time and then every
// execStampFailLogEvery-th, never once per exec.
func TestExecWatcher_StampFailureIsCountedAndLogged(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	w := NewExecWatcher(func(threatdetect.ExecEvent) {})
	w.byCgroup[42] = execTarget{Container: "box-a", TenantID: "tenant-a"}
	w.bootTicks = func() (threatdetect.ProcStartTicks, error) { return 0, errors.New("clock_gettime: EINVAL") }
	const execs = 2*execStampFailLogEvery + 5
	for i := 0; i < execs; i++ {
		w.OnExecEvent(context.Background(), netbpf.ExecEvent{HostPID: uint32(1000 + i), CgroupID: 42, Comm: "sh"}) // #nosec G115 -- small test pids
	}
	if w.StampFailures() != execs {
		t.Fatalf("stamp failures = %d, want %d", w.StampFailures(), execs)
	}
	lines := strings.Count(buf.String(), "boot-clock stamp failed")
	if lines != 3 { // the 1st, the 1000th, the 2000th
		t.Fatalf("logged %d times, want 3:\n%s", lines, buf.String())
	}
	if !strings.Contains(buf.String(), "clock_gettime: EINVAL") {
		t.Fatalf("log does not name the error:\n%s", buf.String())
	}
}

// procPerExecFiles are the /proc/<pid> files a per-exec capture would
// plausibly read; procOpenTrap turns each into a trap.
var procPerExecFiles = []string{"stat", "status", "cgroup", "cmdline"}

// procOpenTrap creates <root>/<pid>/<name> for each name as a FIFO whose
// writer counts every open of it. The paths must not exist yet: replacing a
// file that was just written lets a host file scanner (seen on macOS)
// open the FIFO and count as a read. Opening a FIFO for reading rendezvouses
// with the writer, so ANY open of these paths is seen, whatever code does
// it (readProcStartTime, os.ReadFile, os.Open...), not just calls through
// one helper. The reader gets a stat line (field 22 = start) and EOF.
func procOpenTrap(t *testing.T, root string, pid int, comm string, start threatdetect.ProcStartTicks, names ...string) *atomic.Int64 {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	opens := new(atomic.Int64)
	var stop atomic.Bool
	var wg sync.WaitGroup
	var paths []string
	// Stop the writers: each is blocked in open (waiting for a reader) or
	// probing for its reader to leave. Hold a non-blocking reader open on
	// every FIFO until they have all returned, so a writer woken after a
	// short-lived reader already closed cannot block again.
	t.Cleanup(func() {
		stop.Store(true)
		var readers []*os.File
		for _, p := range paths {
			if f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
				readers = append(readers, f)
			}
		}
		defer func() {
			for _, f := range readers {
				_ = f.Close()
			}
		}()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("procOpenTrap writers did not stop")
		}
	})
	for _, name := range names {
		path := filepath.Join(dir, name)
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("procOpenTrap: %s already exists; traps go on fresh paths", path)
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Skipf("no FIFOs here: %v", err)
		}
		paths = append(paths, path)
		content := []byte(statLine(pid, comm, start))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				f, err := os.OpenFile(path, os.O_WRONLY, 0) // blocks until a reader opens
				if err != nil {
					return
				}
				if stop.Load() {
					_ = f.Close()
					return
				}
				opens.Add(1)
				_, _ = f.Write(content)
				_ = f.Close()
				// Wait for this reader to close before the next blocking
				// open, which would otherwise succeed at once against the
				// same reader and count it twice. A non-blocking writer
				// open fails (ENXIO) once no reader holds the FIFO.
				for !stop.Load() {
					g, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
					if err != nil {
						break
					}
					_ = g.Close()
					time.Sleep(50 * time.Microsecond)
				}
			}
		}()
	}
	return opens
}

// TestExecWatcher_FloodOfNonMatchingExecsReadsNoProc: the whole exec path
// (ring decode → watcher → engine with the miner-signature rule →
// responder with the real host killer, kill_process on) opens nothing under
// /proc/<pid> for a flood of execs no rule matches, and reads the stat
// exactly once for the one exec it kills. The flood's pids are FIFO traps
// (procOpenTrap), so a read added through any code path is caught. The
// stat read must stay off the per-exec path: under an exec flood it is what
// would make the ring consumer fall behind (exec_events_lost).
func TestExecWatcher_FloodOfNonMatchingExecsReadsNoProc(t *testing.T) {
	const initPID, minerPID = 100, 4242
	// The miner's cgroup is a plain file; its stat is a trap created on a
	// fresh path (procOpenTrap must never replace a file just written: a
	// host file scanner reacting to that write can open the FIFO).
	proc := fakeProc(t, map[int]string{initPID: "/lxc.payload.box-a/init.scope"})
	minerDir := filepath.Join(proc, fmt.Sprint(minerPID))
	if err := os.MkdirAll(minerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(minerDir, "cgroup"), []byte("0::/lxc.payload.box-a/user.slice\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const floodPIDs = 8
	var floodOpens []*atomic.Int64
	for i := 0; i < floodPIDs; i++ {
		floodOpens = append(floodOpens, procOpenTrap(t, proc, 10_000+i, "sh", fakeStart(10_000+i), procPerExecFiles...))
	}
	minerStatOpens := procOpenTrap(t, proc, minerPID, "xmrig", fakeStart(minerPID), "stat")

	fx := newResponderFixture(t, false)
	fx.setKill(t, "", true)
	var killed []int
	fx.r.SetProcessKiller(&hostProcessKiller{
		procRoot: proc,
		initPID:  func(string) (int64, error) { return initPID, nil },
		open:     func(p int) (pidHandle, error) { return fakePIDHandle{killed: &killed, pid: p}, nil },
	})
	engine := threatdetect.NewEngine(NewActingSink(fx.findings, fx.r), "b1", false, nil, nil)
	rule, err := threatdetect.NewMinerSignatureRule(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.Register(rule)
	w := NewExecWatcher(engine.OnExec)
	w.procRoot = proc
	w.bootTicks = func() (threatdetect.ProcStartTicks, error) { return fakeStart(minerPID) + 10, nil }
	w.byCgroup[42] = execTarget{Container: "box-a", TenantID: "tenant-a"}

	const flood = 20_000
	ctx := context.Background()
	for i := 0; i < flood; i++ {
		w.OnExecEvent(ctx, netbpf.ExecEvent{HostPID: uint32(10_000 + i%floodPIDs), PPID: 1, CgroupID: 42, Comm: "sh", // #nosec G115 -- small test pids
			Filename: "/usr/bin/sh", Argv: []string{"sh", "-c", "true"}})
	}
	for i, o := range floodOpens {
		if n := o.Load(); n != 0 {
			t.Fatalf("%d non-matching execs opened files under /proc/%d %d times, want 0", flood, 10_000+i, n)
		}
	}
	if len(killed) != 0 {
		t.Fatalf("non-matching flood killed %v", killed)
	}
	if got := fx.findings.byRule(pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE); len(got) != 0 {
		t.Fatalf("non-matching flood raised %d signature findings", len(got))
	}

	w.OnExecEvent(ctx, netbpf.ExecEvent{HostPID: minerPID, PPID: 1, CgroupID: 42, Comm: "xmrig",
		Filename: "/tmp/xmrig", Argv: []string{"./xmrig", "--donate-level", "1"}})
	if n := minerStatOpens.Load(); n != 1 || len(killed) != 1 || killed[0] != minerPID {
		t.Fatalf("matched exec: %d stat opens, kills %v; want 1 open and pid %d killed", n, killed, minerPID)
	}
}

// TestExecWatcher_FanOutDropsSlowSubscriberWithoutBlocking: two subscribers,
// one never reads. The fast one receives every event, the slow one is
// dropped (its channel closed) once its buffer is full, and OnExecEvent
// never blocks on it — the whole run completes inside a deadline far below
// what a blocked send would take.
func TestExecWatcher_FanOutDropsSlowSubscriberWithoutBlocking(t *testing.T) {
	procRoot, cgroupRoot, ino := fakeTree(t, map[int64]string{100: "lxc.payload.box-a"})
	w := newTestWatcher(t, procRoot, cgroupRoot, newFakeCgroupMap())
	w.Reconcile([]incus.ContainerInfo{running("box-a", 100)})
	cg := ino["lxc.payload.box-a"]

	_, fast, cancelFast := w.Subscribe("", 0, 64)
	defer cancelFast()
	_, slow, cancelSlow := w.Subscribe("", 0, 2)
	defer cancelSlow()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10; i++ {
			w.OnExecEvent(context.Background(), kernelEvent(cg, uint32(100+i), "sh", "sh")) // #nosec G115 -- small test loop
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("OnExecEvent blocked on a slow subscriber")
	}

	if n := len(fast); n != 10 {
		t.Fatalf("fast subscriber buffered %d events, want 10", n)
	}
	// The slow subscriber got the first 2, then was dropped: its channel is
	// closed after those.
	var slowGot int
	for ev := range slow {
		slowGot++
		if ev.Container != "box-a" {
			t.Errorf("slow event container = %q", ev.Container)
		}
	}
	if slowGot != 2 {
		t.Fatalf("slow subscriber received %d before being dropped, want 2", slowGot)
	}
	if w.SubscribersDropped() != 1 {
		t.Fatalf("dropped subscribers = %d, want 1", w.SubscribersDropped())
	}
	// The fast one is still live.
	w.OnExecEvent(context.Background(), kernelEvent(cg, 999, "sh", "sh"))
	select {
	case ev := <-fast:
		_ = ev
	case <-time.After(time.Second):
		t.Fatal("fast subscriber stopped receiving after the slow one was dropped")
	}
}

// TestExecWatcher_SubscribeFiltersAndReplays: a container filter delivers
// only that box's events; `since` replays the in-memory ring (newest-last)
// for the window, atomically with the subscription so nothing is duplicated
// or missed between replay and live.
func TestExecWatcher_SubscribeFiltersAndReplays(t *testing.T) {
	procRoot, cgroupRoot, ino := fakeTree(t, map[int64]string{100: "lxc.payload.box-a", 200: "lxc.payload.box-b"})
	w := newTestWatcher(t, procRoot, cgroupRoot, newFakeCgroupMap())
	now := time.Unix(1700000000, 0)
	w.now = func() time.Time { return now }
	w.Reconcile([]incus.ContainerInfo{running("box-a", 100), running("box-b", 200)})
	a, b := ino["lxc.payload.box-a"], ino["lxc.payload.box-b"]

	w.OnExecEvent(context.Background(), kernelEvent(a, 1, "old", "old")) // 10 min ago
	now = now.Add(10 * time.Minute)
	w.OnExecEvent(context.Background(), kernelEvent(a, 2, "sh", "sh"))
	w.OnExecEvent(context.Background(), kernelEvent(b, 3, "sh", "sh"))
	now = now.Add(time.Second)

	replay, ch, cancel := w.Subscribe("box-a", 5*time.Minute, 8)
	defer cancel()
	if len(replay) != 1 || replay[0].Event.HostPID != 2 || replay[0].Container != "box-a" {
		t.Fatalf("replay = %+v, want only box-a's event from the last 5 minutes", replay)
	}
	w.OnExecEvent(context.Background(), kernelEvent(b, 4, "sh", "sh"))
	w.OnExecEvent(context.Background(), kernelEvent(a, 5, "sh", "sh"))
	select {
	case ev := <-ch:
		if ev.Event.HostPID != 5 {
			t.Fatalf("live event pid = %d, want 5 (box-b's 4 filtered out)", ev.Event.HostPID)
		}
	case <-time.After(time.Second):
		t.Fatal("no live event delivered")
	}
	if len(ch) != 0 {
		t.Fatalf("filtered subscriber has %d extra events buffered", len(ch))
	}

	all, _, cancelAll := w.Subscribe("", time.Hour, 8)
	defer cancelAll()
	if len(all) != 5 {
		t.Fatalf("unfiltered hour replay = %d events, want 5", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].At.Before(all[i-1].At) {
			t.Fatalf("replay not oldest-first: %+v", all)
		}
	}
	none, _, cancelNone := w.Subscribe("", 0, 8)
	defer cancelNone()
	if len(none) != 0 {
		t.Fatalf("since=0 replayed %d events, want none", len(none))
	}
}

// The replay ring is bounded: after more events than it holds, only the most
// recent execReplayRing remain.
func TestExecWatcher_ReplayRingIsBounded(t *testing.T) {
	procRoot, cgroupRoot, ino := fakeTree(t, map[int64]string{100: "lxc.payload.box-a"})
	w := newTestWatcher(t, procRoot, cgroupRoot, newFakeCgroupMap())
	w.Reconcile([]incus.ContainerInfo{running("box-a", 100)})
	cg := ino["lxc.payload.box-a"]
	for i := 0; i < execReplayRing+10; i++ {
		w.OnExecEvent(context.Background(), kernelEvent(cg, uint32(i), "sh", "sh")) // #nosec G115 -- bounded test loop
	}
	replay, _, cancel := w.Subscribe("", time.Hour, 1)
	defer cancel()
	if len(replay) != execReplayRing {
		t.Fatalf("replay = %d, want the ring size %d", len(replay), execReplayRing)
	}
	if replay[0].Event.HostPID != 10 || replay[len(replay)-1].Event.HostPID != uint32(execReplayRing+9) {
		t.Fatalf("replay window = pids %d..%d, want 10..%d", replay[0].Event.HostPID, replay[len(replay)-1].Event.HostPID, execReplayRing+9)
	}
}

// Status strings: not started, running, failed, stopped.
func TestExecWatcher_Status(t *testing.T) {
	w := NewExecWatcher(nil)
	if got := w.Status(); got != execTelemetryNotStartedStatus {
		t.Fatalf("initial status = %q", got)
	}
	w.setStatus(execTelemetryUnavailable(fmt.Errorf("netbpf: execwatch: load collection: BTF not found")))
	if got := w.Status(); got != "unavailable (netbpf: execwatch: load collection: BTF not found)" {
		t.Fatalf("failed status = %q", got)
	}
	if !strings.HasPrefix(w.Status(), "unavailable") {
		t.Fatal("unavailable status must start with the word the health loop keys on")
	}
	w.setStatus(execTelemetryOK)
	if got := w.Status(); got != "ok" {
		t.Fatalf("running status = %q", got)
	}
	if w.Lost() != 0 {
		t.Fatalf("Lost() = %d with no kernel object, want 0", w.Lost())
	}
}

// fakeExecRing is an execRingReader. With err set it reports data and
// returns err from ReadInto (a failing ring). With no err it is an empty
// ring; the consumer leaves on ctx cancellation either way. Like the real
// ringbuf.Reader, whose AvailableBytes dereferences the mapping Close unmaps,
// it PANICS when ReadInto or AvailableBytes is called after Close: the
// consumer must close the reader only after its drain loop has returned
// (#2812 review), and a fake that tolerated the old order would hide that.
type fakeExecRing struct {
	err    error
	once   sync.Once
	closed chan struct{}
}

func newFakeExecRing(err error) *fakeExecRing {
	return &fakeExecRing{err: err, closed: make(chan struct{})}
}

func (r *fakeExecRing) useAfterClose(method string) {
	select {
	case <-r.closed:
		panic("fakeExecRing." + method + " called after Close: the consumer must close the reader only after its loop has returned")
	default:
	}
}

func (r *fakeExecRing) ReadInto(*ringbuf.Record) error {
	r.useAfterClose("ReadInto")
	if r.err != nil {
		return r.err
	}
	return os.ErrDeadlineExceeded
}

func (r *fakeExecRing) SetDeadline(time.Time) {}

func (r *fakeExecRing) AvailableBytes() int {
	r.useAfterClose("AvailableBytes")
	if r.err != nil {
		return 1
	}
	return 0
}

func (r *fakeExecRing) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

func (r *fakeExecRing) isClosed() bool {
	select {
	case <-r.closed:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

// A ring consumer that dies on a read error while the watcher is meant to be
// running must not leave the status at "ok": it flips to
// `unavailable (ring consumer exited: …)`, GetSentryStatus reports it, the
// health loop's predicate sees it as down, and open streams are ended.
func TestExecWatcher_ConsumerExitFlipsStatusUnavailable(t *testing.T) {
	w := NewExecWatcher(nil)
	w.setStatus(execTelemetryOK)
	_, ch, cancel := w.Subscribe("", 0, 0)
	defer cancel()

	rd := newFakeExecRing(errors.New("read ring: bad file descriptor"))
	w.wg.Add(1)
	w.consume(context.Background(), rd)

	got := w.Status()
	if !strings.HasPrefix(got, "unavailable (ring consumer exited: ") || !strings.Contains(got, "bad file descriptor") {
		t.Fatalf("status after consumer exit = %q, want unavailable (ring consumer exited: …bad file descriptor…)", got)
	}
	if w.Running() {
		t.Fatal("Running() = true after the consumer exited")
	}
	if !rd.isClosed() {
		t.Fatal("reader not closed after the consumer exited")
	}
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("subscriber received an event, want its channel closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber channel still open after the consumer exited")
	}

	s := NewThreatDetectionServer(threatdetect.NewEngine(&fakeFindingSink{}, "b", false, nil, nil), true, true, "")
	s.SetExecTelemetry(w)
	resp, err := s.GetSentryStatus(secReadCtx(), &pb.GetSentryStatusRequest{})
	if err != nil {
		t.Fatalf("GetSentryStatus: %v", err)
	}
	if resp.GetExecTelemetry() != got {
		t.Fatalf("exec_telemetry = %q, want the watcher's %q", resp.GetExecTelemetry(), got)
	}
	if !execTelemetryDown(resp) {
		t.Fatalf("health loop does not see %q as down; no %q finding would be raised", resp.GetExecTelemetry(), execTelemetrySubject)
	}
}

// A consumer that returns because the watcher is stopping (ctx cancelled)
// leaves the status to Stop.
func TestExecWatcher_ConsumerExitOnShutdownKeepsStatus(t *testing.T) {
	w := NewExecWatcher(nil)
	w.setStatus(execTelemetryOK)
	ctx, cancel := context.WithCancel(context.Background())
	rd := newFakeExecRing(nil)
	w.wg.Add(1)
	go w.consume(ctx, rd)
	cancel()
	w.wg.Wait()
	if got := w.Status(); got != execTelemetryOK {
		t.Fatalf("status after a shutdown exit = %q, want it untouched (%q)", got, execTelemetryOK)
	}
	if !rd.isClosed() {
		t.Fatal("reader not closed on shutdown")
	}
}

// closeRacingRing is shaped like cilium/ebpf v0.22's ringbuf.Reader where it
// matters (#2812 review): AvailableBytes takes no lock and reads the ring
// mapping, which Close unmaps and nils under the reader's lock. On its
// second call AvailableBytes cancels the consumer's ctx and lingers, the
// way a cancel landing mid-call would; if anyone Closes the reader while
// that call is still reading the ring, that is the shutdown crash, and it
// is recorded (and, under -race, reported as a race on ring).
type closeRacingRing struct {
	mu        sync.Mutex
	ring      *int // nil once closed, like Reader.ring
	calls     atomic.Int32
	cancel    func()
	violation atomic.Bool
	closed    chan struct{}
}

func newCloseRacingRing(cancel func()) *closeRacingRing {
	v := 0
	return &closeRacingRing{ring: &v, cancel: cancel, closed: make(chan struct{})}
}

func (r *closeRacingRing) AvailableBytes() int {
	ring := r.ring // unlocked, as in cilium/ebpf
	if ring == nil {
		r.violation.Store(true) // the real reader would nil-deref here
		return 0
	}
	if r.calls.Add(1) == 2 {
		r.cancel()
		select { // give a concurrent closer every chance to run
		case <-r.closed:
			r.violation.Store(true) // closed while this call was reading the ring
		case <-time.After(100 * time.Millisecond):
		}
	}
	return *ring
}

func (r *closeRacingRing) ReadInto(*ringbuf.Record) error { return os.ErrDeadlineExceeded }
func (r *closeRacingRing) SetDeadline(time.Time)          {}

func (r *closeRacingRing) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ring != nil {
		r.ring = nil
		close(r.closed)
	}
	return nil
}

// The reader is closed only after the drain loop has returned, never while
// it may still call the reader's unlocked AvailableBytes; and a cancel still
// ends the consumer promptly and closes the reader.
func TestExecWatcher_ConsumeClosesReaderOnlyAfterLoop(t *testing.T) {
	w := NewExecWatcher(nil)
	w.setStatus(execTelemetryOK)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rd := newCloseRacingRing(cancel)
	w.wg.Add(1)
	start := time.Now()
	go w.consume(ctx, rd)
	waited := make(chan struct{})
	go func() { w.wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("consumer did not return after its ctx was cancelled")
	}
	if rd.violation.Load() {
		t.Fatal("reader closed while the drain loop was still using it (AvailableBytes raced Close)")
	}
	select {
	case <-rd.closed:
	default:
		t.Fatal("reader not closed after the consumer returned")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("consumer took %s to stop after cancel, want about one drain interval", el)
	}
	if got := w.Status(); got != execTelemetryOK {
		t.Fatalf("status after a shutdown exit = %q, want it untouched", got)
	}
}

// Stop ends every subscription (after the status has left "ok") and forgets
// the attribution tables, so a later Start would re-register every box.
func TestExecWatcher_StopEndsSubscriptionsAndClearsTables(t *testing.T) {
	procRoot, cgroupRoot, ino := fakeTree(t, map[int64]string{100: "lxc.payload.box-a"})
	w := newTestWatcher(t, procRoot, cgroupRoot, newFakeCgroupMap())
	w.Reconcile([]incus.ContainerInfo{running("box-a", 100)})
	if _, ok := w.lookup(ino["lxc.payload.box-a"]); !ok {
		t.Fatal("box-a not registered before Stop")
	}
	_, ch, cancel := w.Subscribe("", 0, 0)
	w.Stop()
	defer cancel() // after Stop: must not double-close
	if _, ok := <-ch; ok {
		t.Fatal("subscriber channel delivered an event after Stop, want it closed")
	}
	if got := w.Status(); got != execTelemetryStoppedStatus {
		t.Fatalf("status after Stop = %q, want %q", got, execTelemetryStoppedStatus)
	}
	if _, ok := w.lookup(ino["lxc.payload.box-a"]); ok || w.watchedCount() != 0 {
		t.Fatal("attribution tables survived Stop")
	}
}

// blockingCgroupMap parks WatchCgroup until released, to prove Reconcile
// does not hold w.mu across the kernel map write.
type blockingCgroupMap struct {
	*fakeCgroupMap
	block   bool
	entered chan struct{}
	release chan struct{}
}

func (m *blockingCgroupMap) WatchCgroup(id uint64, idx uint32) error {
	if m.block {
		m.entered <- struct{}{}
		<-m.release
	}
	return m.fakeCgroupMap.WatchCgroup(id, idx)
}

// OnExecEvent (the ring consumer) must keep running while Reconcile is
// parked in a kernel map write: the resolve and the map syscalls happen
// outside w.mu.
func TestExecWatcher_OnExecEventNotBlockedByReconcileMapWrite(t *testing.T) {
	procRoot, cgroupRoot, ino := fakeTree(t, map[int64]string{100: "lxc.payload.box-a", 200: "lxc.payload.box-b"})
	m := &blockingCgroupMap{fakeCgroupMap: newFakeCgroupMap(), entered: make(chan struct{}), release: make(chan struct{})}
	var engineCalls sync.WaitGroup
	w := NewExecWatcher(func(threatdetect.ExecEvent) { engineCalls.Done() })
	w.procRoot, w.cgroupRoot = procRoot, cgroupRoot
	w.maps = m
	w.setStatus(execTelemetryOK)
	w.Reconcile([]incus.ContainerInfo{running("box-a", 100)})

	m.block = true
	reconciled := make(chan struct{})
	go func() {
		defer close(reconciled)
		w.Reconcile([]incus.ContainerInfo{running("box-a", 100), running("box-b", 200)})
	}()
	select {
	case <-m.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("Reconcile never reached the map write")
	}

	engineCalls.Add(1)
	delivered := make(chan struct{})
	go func() {
		w.OnExecEvent(context.Background(), kernelEvent(ino["lxc.payload.box-a"], 7, "sh", "sh"))
		close(delivered)
	}()
	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		close(m.release)
		t.Fatal("OnExecEvent blocked while Reconcile was in a kernel map write (w.mu held across the write)")
	}
	engineCalls.Wait()

	close(m.release)
	<-reconciled
	if _, ok := w.lookup(ino["lxc.payload.box-b"]); !ok {
		t.Fatal("box-b not committed after the map write was released")
	}
}

// When a stopped box's cgroup inode is reused by a box that started in the
// same pass, the stale id's removal must reach the kernel map BEFORE the new
// box's addition — the other order deletes the new box's entry.
func TestWatchedCgroupsReconcile_RemovalBeforeAddOnReusedID(t *testing.T) {
	procRoot, cgroupRoot, ino := fakeTree(t, map[int64]string{100: "lxc.payload.box-old"})
	// box-new's init (pid 200) lives in a cgroup that resolves to the same
	// inode as box-old's (a recycled kernfs id): a symlink to the same dir.
	if err := os.MkdirAll(filepath.Join(procRoot, "200"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "200", "cgroup"), []byte("0::/lxc.payload.box-new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("lxc.payload.box-old", filepath.Join(cgroupRoot, "lxc.payload.box-new")); err != nil {
		t.Fatal(err)
	}
	id := ino["lxc.payload.box-old"]
	if got, err := cgroupIDForPID(procRoot, cgroupRoot, 200); err != nil || got != id {
		t.Fatalf("fixture: box-new id = %d (%v), want the reused %d", got, err, id)
	}

	m := newFakeCgroupMap()
	w := newTestWatcher(t, procRoot, cgroupRoot, m)
	w.Reconcile([]incus.ContainerInfo{running("box-old", 100)})
	m.ops = nil

	w.Reconcile([]incus.ContainerInfo{
		running("box-old", 0, func(c *incus.ContainerInfo) { c.State = "Stopped" }),
		running("box-new", 200),
	})
	want := []string{fmt.Sprintf("unwatch %d", id), fmt.Sprintf("watch %d", id)}
	if fmt.Sprint(m.ops) != fmt.Sprint(want) {
		t.Fatalf("map ops = %v, want %v (removal before addition)", m.ops, want)
	}
	if ids := m.ids(); len(ids) != 1 || ids[0] != id {
		t.Fatalf("kernel map = %v, want the reused id %d watched", ids, id)
	}
	if tgt, ok := w.lookup(id); !ok || tgt.Container != "box-new" {
		t.Fatalf("id %d → %+v (%v), want box-new", id, tgt, ok)
	}
}
