package traffic

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3401: traffic persistence installs into the running collector after a
// degraded start. The collector keeps its in-memory window and its loops; it
// is given the store (SetStore) instead of being replaced, it is never
// started twice, and only flows that close after the store arrived are
// persisted.

// recordingHistory stands in for the Postgres store: it records what the
// collector persists and how often it runs the retention cleanup.
type recordingHistory struct {
	mu       sync.Mutex
	saved    []*pb.Connection
	cleanups int
	savedCh  chan struct{}
}

func newRecordingHistory() *recordingHistory {
	return &recordingHistory{savedCh: make(chan struct{}, 64)}
}

func (h *recordingHistory) SaveConnection(_ context.Context, conn *pb.Connection) error {
	h.mu.Lock()
	h.saved = append(h.saved, conn)
	h.mu.Unlock()
	select {
	case h.savedCh <- struct{}{}:
	default: // a reader that is not waiting must not block persistence
	}
	return nil
}

func (h *recordingHistory) Cleanup(context.Context, int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cleanups++
	return nil
}

func (h *recordingHistory) savedIDs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ids := make([]string, 0, len(h.saved))
	for _, c := range h.saved {
		ids = append(ids, c.Id)
	}
	return ids
}

func (h *recordingHistory) cleanupCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cleanups
}

// newLifecycleTestCollector is newTestCollector with a context and a config,
// so Start and Stop can run (no conntrack monitor, no incus client).
func newLifecycleTestCollector(t *testing.T) *Collector {
	t.Helper()
	c := newTestCollector()
	c.config = DefaultCollectorConfig()
	c.ctx, c.cancel = context.WithCancel(context.Background())
	t.Cleanup(c.Stop)
	return c
}

func webFlow(port uint16, bytes int64) EBPFFlow {
	now := time.Now()
	return EBPFFlow{
		ContainerName: "web-container", ContainerIP: "10.100.0.42", Protocol: "tcp",
		SrcIP: "10.100.0.42", SrcPort: port, DstIP: "192.0.2.10", DstPort: 443,
		Bytes: bytes, Packets: 3, First: now.Add(-time.Second), Last: now,
	}
}

func waitSaved(t *testing.T, h *recordingHistory, n int) {
	t.Helper()
	for range n {
		select {
		case <-h.savedCh:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for %d persisted flows; got %v", n, h.savedIDs())
		}
	}
}

// The store is installed once and read live; a second store or a nil one is
// refused and leaves the first in place.
func TestCollectorSetStore_InstallsOnceAndIsReadLive(t *testing.T) {
	c := newTestCollector()
	if c.GetStore() != nil {
		t.Fatal("a collector built without a store reports one")
	}
	if c.SetStore(nil) {
		t.Error("SetStore(nil) reported an install")
	}
	first, second := &Store{}, &Store{}
	if !c.SetStore(first) {
		t.Fatal("SetStore on a store-less collector was refused")
	}
	if got := c.GetStore(); got != first {
		t.Errorf("GetStore after install = %p, want the installed store %p", got, first)
	}
	if c.SetStore(second) {
		t.Error("a second SetStore replaced the installed store")
	}
	if got := c.GetStore(); got != first {
		t.Errorf("GetStore after a refused second install = %p, want the first %p", got, first)
	}
}

// A collector built with a store (the startup path) refuses a later one.
func TestCollectorSetStore_RefusedWhenBuiltWithStore(t *testing.T) {
	boot := &Store{}
	c, err := NewCollector(DefaultCollectorConfig(), nil, boot, nil)
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	t.Cleanup(c.Stop)
	if c.SetStore(&Store{}) {
		t.Error("SetStore replaced the store the collector was built with")
	}
	if c.GetStore() != boot {
		t.Error("GetStore is not the store the collector was built with")
	}
}

// Installing the store neither restarts the collector nor clears its
// in-memory window: the live flows gathered before the store are still
// served, and Start ran its loops exactly once.
func TestCollectorSetStore_KeepsWindowAndDoesNotRestart(t *testing.T) {
	c := newLifecycleTestCollector(t)
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	c.IngestEBPFFlows([]EBPFFlow{webFlow(51000, 100), webFlow(51001, 200)})

	if !c.SetStore(&Store{}) {
		t.Fatal("SetStore refused on a running store-less collector")
	}
	if got := len(c.GetConnections("web-container")); got != 2 {
		t.Errorf("live connections after install = %d, want the 2 gathered before it", got)
	}
	if got := c.loopStarts(); got != 1 {
		t.Errorf("collector loops started %d times, want once (install must not restart it)", got)
	}
}

// Start runs once; a second call is refused and starts nothing.
func TestCollectorStart_SecondCallRefused(t *testing.T) {
	c := newLifecycleTestCollector(t)
	if err := c.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if err := c.Start(); !errors.Is(err, ErrCollectorStarted) {
		t.Errorf("second Start = %v, want ErrCollectorStarted", err)
	}
	if got := c.loopStarts(); got != 1 {
		t.Errorf("collector loops started %d times, want once", got)
	}
}

// Decision on #3401: flows that closed before the store arrived are not
// persisted (no buffering, as for alerts in #3335 Q15). A flow that was
// still live when the store arrived is persisted when it closes, with its
// full counters, and every flow that opens later is persisted as usual.
func TestCollectorSetStore_PersistsOnlyFlowsClosedAfterInstall(t *testing.T) {
	c := newTestCollector()
	h := newRecordingHistory()

	// Closed while the store is absent: dropped.
	c.IngestEBPFFlows([]EBPFFlow{webFlow(51000, 100)})
	c.IngestEBPFFlows(nil)

	// Live across the install, closed after it: persisted.
	c.IngestEBPFFlows([]EBPFFlow{webFlow(51001, 4096)})
	if !c.installHistory(&Store{}, h) {
		t.Fatal("install refused")
	}
	c.IngestEBPFFlows([]EBPFFlow{webFlow(51002, 7)})
	c.IngestEBPFFlows(nil) // closes 51002
	// 51001 closed when 51002 replaced it; 51002 closed on the empty poll.
	waitSaved(t, h, 2)
	time.Sleep(20 * time.Millisecond) // let a wrongly persisted third flow land

	want := map[string]bool{ebpfFlowID(webFlow(51001, 0)): true, ebpfFlowID(webFlow(51002, 0)): true}
	ids := h.savedIDs()
	if len(ids) != 2 {
		t.Fatalf("persisted flows = %v, want exactly the two that closed after the install", ids)
	}
	for _, id := range ids {
		if !want[id] {
			t.Errorf("persisted %s, which closed before the store arrived", id)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, conn := range h.saved {
		if conn.Id == ebpfFlowID(webFlow(51001, 0)) && conn.BytesSent != 4096 {
			t.Errorf("flow live across the install persisted %d bytes, want its full 4096", conn.BytesSent)
		}
	}
}

// The retention cleanup loop runs only while the collector runs and only
// with a store, and it is started once whichever arrives first.
func TestCollectorSetStore_CleanupLoopStartsOnce(t *testing.T) {
	cases := []struct {
		name  string
		steps func(c *Collector, h *recordingHistory)
		want  int
	}{
		{"install before start", func(c *Collector, h *recordingHistory) {
			c.installHistory(&Store{}, h)
			_ = c.Start()
		}, 1},
		{"install after start", func(c *Collector, h *recordingHistory) {
			_ = c.Start()
			c.installHistory(&Store{}, h)
		}, 1},
		{"second install after start", func(c *Collector, h *recordingHistory) {
			_ = c.Start()
			c.installHistory(&Store{}, h)
			c.installHistory(&Store{}, h)
		}, 1},
		{"start twice with a store", func(c *Collector, h *recordingHistory) {
			c.installHistory(&Store{}, h)
			_ = c.Start()
			_ = c.Start()
		}, 1},
		{"install without start", func(c *Collector, h *recordingHistory) {
			c.installHistory(&Store{}, h)
		}, 0},
		{"install after stop", func(c *Collector, h *recordingHistory) {
			_ = c.Start()
			c.Stop()
			c.installHistory(&Store{}, h)
		}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newLifecycleTestCollector(t)
			c.config.CleanupInterval = time.Millisecond
			h := newRecordingHistory()
			tc.steps(c, h)
			if got := c.cleanupStarts(); got != tc.want {
				t.Errorf("cleanup loops started = %d, want %d", got, tc.want)
			}
			if tc.want == 0 {
				return
			}
			deadline := time.Now().Add(5 * time.Second)
			for h.cleanupCount() == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if h.cleanupCount() == 0 {
				t.Error("the cleanup loop never ran against the installed store")
			}
		})
	}
}

// The interleaving a plain flag would miss: the store is swapped in, Start
// runs and sees it (starting the cleanup loop), then the install's own
// post-swap step runs. The loop still starts once.
func TestCollectorSetStore_StartBetweenSwapAndInstallStartsCleanupOnce(t *testing.T) {
	c := newLifecycleTestCollector(t)
	c.hist.Store(&history{store: &Store{}, w: newRecordingHistory()})
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	c.storeInstalled()
	if got := c.cleanupStarts(); got != 1 {
		t.Errorf("cleanup loops started = %d, want 1", got)
	}
}

// Readers and persistence run while the store is installed, so -race
// catches a store field that is still read raw.
func TestCollectorSetStore_ConcurrentReadersAreRaceFree(t *testing.T) {
	c := newTestCollector()
	h := newRecordingHistory()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	ports := [4]uint16{40000, 40001, 40002, 40003}
	for i := range ports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				_ = c.GetStore()
				c.PersistEBPFFlows([]EBPFFlow{webFlow(ports[i], int64(n))})
			}
		}()
	}
	c.installHistory(&Store{}, h)
	time.Sleep(10 * time.Millisecond)
	close(stop)
	wg.Wait()
	if c.GetStore() == nil {
		t.Error("store missing after concurrent install")
	}
}

// Stop is safe to call twice (the daemon's shutdown and a test cleanup).
func TestCollectorStop_Idempotent(t *testing.T) {
	c := newLifecycleTestCollector(t)
	_ = c.Start()
	c.Stop()
	c.Stop()
	if err := c.Start(); err == nil {
		t.Error("Start after Stop succeeded; a stopped collector must stay stopped")
	}
}
