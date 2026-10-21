package server

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/threatdetect"
)

// hasherProc is a fake /proc for the exec hasher: <root>/<pid>/exe holding
// content and <root>/<pid>/stat with start time start.
func hasherProc(t *testing.T, root string, pid int, content string, start threatdetect.ProcStartTicks) {
	t.Helper()
	writeStat(t, root, pid, "proc", start)
	if err := os.WriteFile(filepath.Join(root, strconv.Itoa(pid), "exe"), []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newTestHasher(root string) (*execHasher, *[]threatdetect.ExecEvent) {
	var got []threatdetect.ExecEvent
	h := newExecHasher(func(ev threatdetect.ExecEvent) { got = append(got, ev) })
	h.procRoot = root
	return h, &got
}

// TestExecHasher_PinsPIDBeforeHashing (#2768 item 2): /proc/<pid>/exe is
// hashed only for the process the exec event named. After exe is opened,
// the pid's start time (/proc/<pid>/stat field 22) is checked against the
// event's decode stamp: a process that started after the stamp (beyond one
// tick of slack, startedAfterStamp) took the pid later, so the event is
// dropped instead of getting another binary's hash. An event with no stamp
// cannot be pinned and is dropped.
func TestExecHasher_PinsPIDBeforeHashing(t *testing.T) {
	const pid = 4242
	tests := []struct {
		name      string
		start     threatdetect.ProcStartTicks // the exec event's
		noStat    bool
		wantSum   bool
		wantMoved uint64
	}{
		{name: "stamped in the tick it started", start: fakeStart(pid), wantSum: true},
		{name: "stamped later than it started", start: fakeStart(pid) + 9, wantSum: true},
		{name: "within the one-tick slack", start: fakeStart(pid) - 1, wantSum: true},
		{name: "pid now held by a process started after the stamp", start: fakeStart(pid) - 2, wantMoved: 1},
		{name: "pid now held by a much newer process", start: fakeStart(pid) - 900, wantMoved: 1},
		{name: "no stamp cannot be pinned", start: 0, wantMoved: 1},
		{name: "stat gone", start: fakeStart(pid), noStat: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			hasherProc(t, root, pid, "miner", fakeStart(pid))
			if tt.noStat {
				if err := os.Remove(filepath.Join(root, strconv.Itoa(pid), "stat")); err != nil {
					t.Fatal(err)
				}
			}
			h, got := newTestHasher(root)
			h.process(threatdetect.ExecEvent{PID: pid, StartTime: tt.start, Container: "box-a"})
			if tt.wantSum {
				if len(*got) != 1 || (*got)[0].SHA256 != sha256Hex("miner") || (*got)[0].Container != "box-a" {
					t.Fatalf("redelivered %+v, want one event with the binary's hash", *got)
				}
			} else if len(*got) != 0 {
				t.Fatalf("redelivered %+v for a process that is not the exec's", *got)
			}
			if m := h.pidMoved.Load(); m != tt.wantMoved {
				t.Fatalf("pidMoved = %d, want %d", m, tt.wantMoved)
			}
		})
	}
}

// TestExecHasher_ComparesStartTimeAfterOpen: the order is what makes the pin
// hold. If the pid is reused just before exe is opened, the opened file is
// the newcomer's binary; only a start-time read AFTER the open sees the
// newcomer and drops the event.
func TestExecHasher_ComparesStartTimeAfterOpen(t *testing.T) {
	const pid = 4242
	root := t.TempDir()
	hasherProc(t, root, pid, "miner", fakeStart(pid))
	h, got := newTestHasher(root)
	h.open = func(name string) (*os.File, error) {
		// The matched process exits and an unrelated one takes its pid,
		// starting well after the exec was stamped.
		hasherProc(t, root, pid, "unrelated", fakeStart(pid)+100)
		return os.Open(name) // #nosec G304 -- test fixture path
	}
	h.process(threatdetect.ExecEvent{PID: pid, StartTime: fakeStart(pid)})
	if len(*got) != 0 {
		t.Fatalf("redelivered %+v: the newcomer's hash was attributed to the matched exec", *got)
	}
}

// TestExecHasher_CachesByFileIdentity (#2768 item 3): a binary already hashed
// is not read again, keyed by (device, inode, size, mtime, ctime) of the
// opened executable, so the thousandth /bin/sh costs an open and a stat. A
// changed file (new content, or the same size and mtime put back) is hashed
// again. The cache is bounded.
func TestExecHasher_CachesByFileIdentity(t *testing.T) {
	root := t.TempDir()
	hasherProc(t, root, 100, "busybox", fakeStart(100))
	// pid 200 runs the same file: its exe is a link to it, as in /proc.
	writeStat(t, root, 200, "proc", fakeStart(200))
	if err := os.Symlink(filepath.Join(root, "100", "exe"), filepath.Join(root, "200", "exe")); err != nil {
		t.Fatal(err)
	}
	h, got := newTestHasher(root)
	ev := func(pid uint32) threatdetect.ExecEvent {
		return threatdetect.ExecEvent{PID: pid, StartTime: fakeStart(int(pid))}
	}
	h.process(ev(100))
	h.process(ev(200))
	h.process(ev(100))
	if n := h.hashed.Load(); n != 1 {
		t.Fatalf("binary read %d times, want 1 (cache by file identity)", n)
	}
	if len(*got) != 3 {
		t.Fatalf("redelivered %d events, want 3: a cache hit is still delivered", len(*got))
	}
	for _, e := range *got {
		if e.SHA256 != sha256Hex("busybox") {
			t.Fatalf("event %+v: want the cached hash", e)
		}
	}

	// Replaced content of a different size: hashed again.
	exe := filepath.Join(root, "100", "exe")
	if err := os.WriteFile(exe, []byte("xmrig-renamed"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.process(ev(200))
	if n := h.hashed.Load(); n != 2 || (*got)[3].SHA256 != sha256Hex("xmrig-renamed") {
		t.Fatalf("after a rewrite: reads = %d, sum = %s, want a fresh hash", n, (*got)[3].SHA256)
	}

	// Same size, mtime set back: ctime still moves, so it is hashed again.
	st, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(exe, []byte("xmrig-RENAMED"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(exe, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	h.process(ev(100))
	if n := h.hashed.Load(); n != 3 || (*got)[4].SHA256 != sha256Hex("xmrig-RENAMED") {
		t.Fatalf("same size and mtime, new content: reads = %d, sum = %s, want a fresh hash", n, (*got)[4].SHA256)
	}

	// Bounded: distinct binaries beyond the cap never grow it past the cap.
	h.cacheMax = 3
	for pid := 300; pid < 310; pid++ {
		hasherProc(t, root, pid, "bin-"+strconv.Itoa(pid), fakeStart(pid))
		h.process(ev(uint32(pid)))
	}
	if n := len(h.cache); n > 3 {
		t.Fatalf("cache holds %d entries, want at most the cap 3", n)
	}
}

// TestExecHasher_DropsAreCounted: Request never blocks the exec path; a
// full queue drops the request and counts it in Dropped, the number
// GetSentryStatus reports as exec_hashes_dropped.
func TestExecHasher_DropsAreCounted(t *testing.T) {
	h, _ := newTestHasher(t.TempDir())
	for i := 0; i < execHashQueue+5; i++ {
		h.Request(threatdetect.ExecEvent{PID: 1})
	}
	if d := h.Dropped(); d != 5 {
		t.Fatalf("Dropped() = %d, want 5", d)
	}
}
