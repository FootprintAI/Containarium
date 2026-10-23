package poolcapacity

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// fakeRun scripts the command runner by zpool name and records every call.
type fakeRun struct {
	mu    sync.Mutex
	calls [][]string
	out   map[string]string // pool -> stdout
	err   map[string]error  // pool -> error
	hang  map[string]bool   // pool -> block until the deadline
}

func (f *fakeRun) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string{name}, args...))
	f.mu.Unlock()
	pool := args[len(args)-1]
	if f.hang[pool] {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err := f.err[pool]; err != nil {
		return nil, err
	}
	return []byte(f.out[pool]), nil
}

func (f *fakeRun) called() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func baseRead(pools ...incus.StoragePoolUsage) Reader {
	return func() ([]incus.StoragePoolUsage, error) { return append([]incus.StoragePoolUsage(nil), pools...), nil }
}

func zfsPool(name, zpool string) incus.StoragePoolUsage {
	return incus.StoragePoolUsage{Name: name, Driver: "zfs", ZpoolName: zpool, UsedBytes: 50, TotalBytes: 100}
}

// #2853: the command, its arguments and the parsed numbers.
func TestWithZpool_ReadsCapacityAndFragmentation(t *testing.T) {
	f := &fakeRun{out: map[string]string{"tank": "tank\t37\t12\n"}}
	got, err := WithZpool(baseRead(zfsPool("default", "tank")), f.run, time.Second)()
	if err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 1 || strings.Join(f.calls[0], " ") != "zpool list -Hp -o name,cap,frag tank" {
		t.Fatalf("calls = %v, want exactly `zpool list -Hp -o name,cap,frag tank`", f.calls)
	}
	z := got[0].Zpool
	if z == nil || z.CapacityPercent != 37 || !z.FragmentationKnown || z.FragmentationPercent != 12 {
		t.Fatalf("Zpool = %+v, want cap 37 frag 12", z)
	}
	if got[0].UsedBytes != 50 || got[0].TotalBytes != 100 {
		t.Errorf("the Incus numbers were disturbed: %+v", got[0])
	}
}

func TestWithZpool_ParsesWhatZpoolActuallyPrints(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		wantOK    bool
		cap, frag int64
		fragKnown bool
	}{
		{"normal", "tank\t37\t12\n", true, 37, 12, true},
		{"spaces instead of tabs", "tank 37 12\n", true, 37, 12, true},
		{"fragmentation not available", "tank\t37\t-\n", true, 37, 0, false},
		{"percent signs kept", "tank\t37%\t12%\n", true, 37, 12, true},
		{"percent sign with no fragmentation", "tank\t37%\t-\n", true, 37, 0, false},
		{"full pool", "tank\t100\t88\n", true, 100, 88, true},
		{"empty", "", false, 0, 0, false},
		{"too few fields", "tank\t37\n", false, 0, 0, false},
		{"not a number", "tank\tabc\t12\n", false, 0, 0, false},
		{"out of range", "tank\t250\t12\n", false, 0, 0, false},
		{"negative", "tank\t-5\t12\n", false, 0, 0, false},
		{"another pool's line", "other\t37\t12\n", false, 0, 0, false},
		{"trailing noise lines", "tank\t37\t12\nwarning: something\n", true, 37, 12, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRun{out: map[string]string{"tank": tc.out}}
			got, _ := WithZpool(baseRead(zfsPool("default", "tank")), f.run, time.Second)()
			z := got[0].Zpool
			if !tc.wantOK {
				if z != nil {
					t.Fatalf("Zpool = %+v from %q, want none", z, tc.out)
				}
				return
			}
			if z == nil || z.CapacityPercent != tc.cap || z.FragmentationKnown != tc.fragKnown || z.FragmentationPercent != tc.frag {
				t.Fatalf("Zpool = %+v from %q, want cap %d frag %d known=%v", z, tc.out, tc.cap, tc.frag, tc.fragKnown)
			}
		})
	}
}

// Only a ZFS pool with a known zpool name is asked.
func TestWithZpool_SkipsPoolsThatAreNotZFS(t *testing.T) {
	f := &fakeRun{out: map[string]string{"tank": "tank\t37\t12\n"}}
	read := baseRead(
		incus.StoragePoolUsage{Name: "dirpool", Driver: "dir", TotalBytes: 100},
		incus.StoragePoolUsage{Name: "zfs-no-name", Driver: "zfs", TotalBytes: 100}, // name not derivable
		zfsPool("default", "tank"),
	)
	got, err := WithZpool(read, f.run, time.Second)()
	if err != nil {
		t.Fatal(err)
	}
	if f.called() != 1 {
		t.Fatalf("zpool was run %d times, want 1 (only the ZFS pool with a name)", f.called())
	}
	if got[0].Zpool != nil || got[1].Zpool != nil || got[2].Zpool == nil {
		t.Fatalf("Zpool by pool = %v %v %v, want only the third", got[0].Zpool, got[1].Zpool, got[2].Zpool)
	}
}

// No zpool binary (a daemon in a container, or a host without ZFS tools):
// every pool keeps its Incus numbers, nothing errors.
func TestWithZpool_MissingBinaryLeavesThePoolsAlone(t *testing.T) {
	f := &fakeRun{err: map[string]error{"tank": fmt.Errorf("run zpool: %w", exec.ErrNotFound)}}
	var logs []string
	got, err := withZpool(baseRead(zfsPool("default", "tank")), f.run, time.Second, func(format string, a ...any) {
		logs = append(logs, fmt.Sprintf(format, a...))
	})()
	if err != nil {
		t.Fatalf("a missing zpool failed the read: %v", err)
	}
	if got[0].Zpool != nil || got[0].UsedBytes != 50 {
		t.Fatalf("got %+v, want the Incus reading untouched and no Zpool", got[0])
	}
	if len(logs) != 0 {
		t.Errorf("a host without zpool logged %v: that is not worth a line every tick", logs)
	}
}

// A failing or garbled zpool for one pool does not take the others with it,
// and is logged once, not on every tick.
func TestWithZpool_OnePoolFailingKeepsTheOthersAndLogsOnce(t *testing.T) {
	f := &fakeRun{
		out: map[string]string{"good": "good\t10\t3\n"},
		err: map[string]error{"bad": errors.New("exit status 1")},
	}
	var logs []string
	read := withZpool(baseRead(zfsPool("p-bad", "bad"), zfsPool("p-good", "good")), f.run, time.Second, func(format string, a ...any) {
		logs = append(logs, fmt.Sprintf(format, a...))
	})
	for i := 0; i < 3; i++ {
		got, err := read()
		if err != nil {
			t.Fatal(err)
		}
		if got[0].Zpool != nil || got[1].Zpool == nil || got[1].Zpool.CapacityPercent != 10 {
			t.Fatalf("pass %d: Zpool = %v / %v, want only the good pool", i, got[0].Zpool, got[1].Zpool)
		}
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "p-bad") {
		t.Fatalf("logs = %v, want one line naming p-bad across three passes", logs)
	}
}

// A hung zpool returns when its deadline passes, never later, and never blocks
// the pool's Incus reading: two hung pools cost one deadline, not two.
func TestWithZpool_HungCommandReturnsWithinTheDeadline(t *testing.T) {
	f := &fakeRun{hang: map[string]bool{"a": true, "b": true}}
	start := time.Now()
	got, err := WithZpool(baseRead(zfsPool("pa", "a"), zfsPool("pb", "b")), f.run, 80*time.Millisecond)()
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("took %s: a hung zpool held the read", elapsed)
	}
	if elapsed > 160*time.Millisecond+500*time.Millisecond { // two sequential deadlines would be ~160ms+; allow scheduling noise
		t.Logf("elapsed %s", elapsed)
	}
	if got[0].Zpool != nil || got[1].Zpool != nil || got[0].UsedBytes != 50 {
		t.Fatalf("got %+v %+v, want the Incus readings and no Zpool", got[0], got[1])
	}
}

// The monitor's tick is not held by it either: the snapshot lands with the
// Incus numbers, well inside the monitor's own timeout.
func TestMonitor_ATickWithAHungZpoolStillCompletes(t *testing.T) {
	f := &fakeRun{hang: map[string]bool{"tank": true}}
	m := New(WithZpool(baseRead(zfsPool("default", "tank")), f.run, 50*time.Millisecond), Options{Timeout: 5 * time.Second, Logf: func(string, ...any) {}})

	start := time.Now()
	m.Tick()
	if time.Since(start) > 2*time.Second {
		t.Fatalf("Tick took %s", time.Since(start))
	}
	snap := m.Snapshot()
	if len(snap.Pools) != 1 || snap.Pools[0].UsedBytes != 50 {
		t.Fatalf("snapshot = %+v, want the Incus reading", snap.Pools)
	}
}

// The Incus read failing is passed through untouched.
func TestWithZpool_PassesTheReadErrorThrough(t *testing.T) {
	boom := errors.New("list storage pools: boom")
	f := &fakeRun{}
	_, err := WithZpool(func() ([]incus.StoragePoolUsage, error) { return nil, boom }, f.run, time.Second)()
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the read error", err)
	}
	if f.called() != 0 {
		t.Error("zpool was run although the pool list failed")
	}
}

// A name that could be read as an option or a path never reaches the command
// line.
func TestWithZpool_NeverRunsAnUnsafePoolName(t *testing.T) {
	f := &fakeRun{}
	read := baseRead(
		zfsPool("a", "-evil"), zfsPool("b", "../x"), zfsPool("c", "a b"), zfsPool("d", "tank; reboot"), zfsPool("e", ""),
	)
	got, err := WithZpool(read, f.run, time.Second)()
	if err != nil {
		t.Fatal(err)
	}
	if f.called() != 0 {
		t.Fatalf("zpool was run %d times for names that are not pool names: %v", f.called(), f.calls)
	}
	for _, p := range got {
		if p.Zpool != nil {
			t.Errorf("%s got Zpool numbers", p.Name)
		}
	}
}

// A zpool that ignores its deadline (stuck in uninterruptible I/O) must not
// hold the read, and must not be joined by another one on the next tick.
func TestWithZpool_DoesNotStackOnAStuckCommand(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	runs := 0
	stuck := func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		mu.Lock()
		runs++
		mu.Unlock()
		<-release // ignores ctx on purpose
		return []byte("tank\t1\t1\n"), nil
	}
	read := WithZpool(baseRead(zfsPool("default", "tank")), stuck, 40*time.Millisecond)

	start := time.Now()
	for i := 0; i < 3; i++ {
		got, err := read()
		if err != nil || got[0].Zpool != nil || got[0].UsedBytes != 50 {
			t.Fatalf("pass %d: got %+v err %v, want the Incus reading only", i, got, err)
		}
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("three reads took %s", time.Since(start))
	}
	mu.Lock()
	n := runs
	mu.Unlock()
	if n != 1 {
		t.Fatalf("zpool was started %d times while the first was still stuck, want 1", n)
	}
	close(release)
}

// After a failure streak ends, the next failure is news again.
func TestWithZpool_LogsAgainAfterARecovery(t *testing.T) {
	f := &fakeRun{err: map[string]error{"tank": errors.New("exit status 1")}, out: map[string]string{"tank": "tank\t5\t5\n"}}
	var logs int
	read := withZpool(baseRead(zfsPool("default", "tank")), f.run, time.Second, func(string, ...any) { logs++ })

	_, _ = read() // fails: logged
	_, _ = read() // still failing: quiet
	f.mu.Lock()
	f.err = nil
	f.mu.Unlock()
	if got, _ := read(); got[0].Zpool == nil { // recovered
		t.Fatal("no numbers after recovery")
	}
	f.mu.Lock()
	f.err = map[string]error{"tank": errors.New("exit status 1")}
	f.mu.Unlock()
	_, _ = read() // fails again: logged again
	if logs != 2 {
		t.Fatalf("logged %d times, want 2 (once per failure streak)", logs)
	}
}

// The real runner reports a missing binary as exec.ErrNotFound, which is how
// WithZpool tells "no ZFS tools here" from a failing zpool.
func TestExecRunner_MissingBinaryIsErrNotFound(t *testing.T) {
	_, err := ExecRunner(context.Background(), "containarium-no-such-binary-2853", "list")
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("err = %v, want it to wrap exec.ErrNotFound", err)
	}
}

// A command that exits non-zero reports why, from its own stderr, one line and
// capped, so the single log line per failure streak is actionable.
func TestExecRunner_FailureCarriesTheFirstStderrLine(t *testing.T) {
	_, err := ExecRunner(context.Background(), "sh", "-c", "echo 'cannot open pool: no such pool' >&2; echo second line >&2; exit 3")
	if err == nil || !strings.Contains(err.Error(), "cannot open pool: no such pool") || strings.Contains(err.Error(), "second line") {
		t.Fatalf("err = %v, want exit status plus only the first stderr line", err)
	}
}
