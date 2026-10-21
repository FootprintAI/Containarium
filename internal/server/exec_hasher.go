package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/footprintai/containarium/internal/threatdetect"
)

// Exec hasher (#2638; design component 5): the miner-signature rule's hash
// matcher needs the SHA-256 of the exec'd binary, which is far too slow to
// compute on the exec ring's consumer goroutine. The rule asks for it only
// when hash entries exist and no name/argv entry matched; this worker hashes
// /proc/<pid>/exe off that path and redelivers the event with SHA256 set.
// Best effort by design: the process may be gone, the binary too large, or
// the budget exceeded — then no hash and no second delivery.
//
// Pinned (#2768): the request can wait in the queue while the process exits
// and its pid is reused, so the hash is attributed to the event only when
// the process holding the pid AFTER exe is opened did not start after the
// event's decode stamp (/proc/<pid>/stat field 22 against ExecEvent.StartTime,
// startedAfterStamp: the same test the kill applies, #2765/#2893). A
// newcomer that took the pid while the request waited started after the
// stamp and is refused; while the process holding the pid lives, the opened
// exe is its image. A process that exec'd again under the same pid keeps its
// start time: its newer image is what gets hashed, and the kill targets
// that same process.
//
// Cached (#2768): a binary already hashed is not read again, keyed by the
// opened file's (device, inode, size, mtime, ctime), so a busy host's
// thousandth /bin/sh costs an open and two stats, and the queue drains
// instead of dropping. Drops that still happen are counted in Dropped,
// reported as GetSentryStatus.exec_hashes_dropped.

const (
	// execHashMaxBytes caps the binary size hashed.
	execHashMaxBytes = 64 << 20
	// execHashBudget caps the wall time spent on one binary.
	execHashBudget = 200 * time.Millisecond
	// execHashQueue is the pending-request depth; a full queue drops the
	// request (counted) rather than blocking the exec path.
	execHashQueue = 64
	// execHashCacheMax bounds the hash cache; past it an arbitrary entry is
	// evicted per insert.
	execHashCacheMax = 4096
)

var (
	errExecHashTooLarge = errors.New("executable larger than the hash cap")
	errExecHashBudget   = errors.New("hash budget exceeded")
)

type execHasher struct {
	procRoot string
	maxBytes int64
	budget   time.Duration
	deliver  func(threatdetect.ExecEvent)
	queue    chan threatdetect.ExecEvent
	dropped  atomic.Int64
	failed   atomic.Uint64
	// pidMoved counts events dropped because the pid no longer held the
	// exec's process (or the event had no start time to pin it by).
	pidMoved atomic.Uint64
	// hashed counts full reads of a binary (cache misses).
	hashed atomic.Uint64
	open   func(name string) (*os.File, error)
	// cache maps an executable's identity to its hex SHA-256. Touched only
	// by the worker goroutine (process), so it needs no lock.
	cache    map[exeIdentity]string
	cacheMax int
}

// exeIdentity is the hash-cache key of an executable; see exeIdentityOf.
type exeIdentity struct {
	dev, ino     uint64
	size         int64
	mtime, ctime int64 // ns
}

// Dropped is the count of requests dropped on a full queue.
func (h *execHasher) Dropped() int64 { return h.dropped.Load() }

// newExecHasher builds a hasher that redelivers hashed events to deliver
// (the engine's OnExec). Run starts the worker.
func newExecHasher(deliver func(threatdetect.ExecEvent)) *execHasher {
	return &execHasher{
		procRoot: execProcRoot,
		maxBytes: execHashMaxBytes,
		budget:   execHashBudget,
		deliver:  deliver,
		queue:    make(chan threatdetect.ExecEvent, execHashQueue),
		open:     os.Open,
		cache:    make(map[exeIdentity]string),
		cacheMax: execHashCacheMax,
	}
}

// Request queues ev for hashing without ever blocking the caller (the exec
// ring consumer). It is RuleContext.HashExec.
func (h *execHasher) Request(ev threatdetect.ExecEvent) {
	select {
	case h.queue <- ev:
	default:
		if n := h.dropped.Add(1); n == 1 || n%100 == 0 {
			log.Printf("[exec-hasher] queue full (cap %d): %d hash requests dropped so far", execHashQueue, n)
		}
	}
}

// Run hashes queued events until ctx ends.
func (h *execHasher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-h.queue:
			h.process(ev)
		}
	}
}

func (h *execHasher) process(ev threatdetect.ExecEvent) {
	sum, err := h.hashPinned(ev)
	if err != nil {
		// Mostly a process that already exited; log the first and every
		// 100th so an operator relying on sha256 entries can see hashing
		// is not happening.
		if n := h.failed.Add(1); n == 1 || n%100 == 0 {
			log.Printf("[exec-hasher] pid %d (%s): %v (%d failed so far)", ev.PID, ev.Container, err, n)
		}
		return
	}
	ev.SHA256 = sum
	h.deliver(ev)
}

// errExecHashPIDMoved: the pid no longer holds the exec's process.
var errExecHashPIDMoved = errors.New("pid no longer holds the exec's process")

// hashPinned opens /proc/<pid>/exe, THEN confirms the pid still holds the
// exec's process by its start time, then hashes the opened file or returns
// its cached hash.
func (h *execHasher) hashPinned(ev threatdetect.ExecEvent) (string, error) {
	// #nosec G304 -- procRoot is a constant (or a test fixture) and pid a
	// number from the kernel's exec record.
	f, err := h.open(filepath.Join(h.procRoot, strconv.FormatUint(uint64(ev.PID), 10), "exe"))
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	cur, err := readProcStartTime(h.procRoot, ev.PID)
	if err != nil {
		return "", err
	}
	// An exec with no stamp (0: the boot clock could not be read) is refused
	// here too: every tenant process started more than a tick after boot.
	if startedAfterStamp(cur, ev.StartTime) {
		h.pidMoved.Add(1)
		return "", fmt.Errorf("started at %d ticks, after the exec was seen at %d: %w", cur, ev.StartTime, errExecHashPIDMoved)
	}
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	id, cacheable := exeIdentityOf(st)
	if cacheable {
		if sum, ok := h.cache[id]; ok {
			return sum, nil
		}
	}
	h.hashed.Add(1)
	sum, err := hashOpenFile(f, st.Size(), h.maxBytes, h.budget)
	if err != nil {
		return "", err
	}
	if cacheable {
		if len(h.cache) >= h.cacheMax {
			for k := range h.cache {
				delete(h.cache, k)
				break
			}
		}
		h.cache[id] = sum
	}
	return sum, nil
}

// hashOpenFile hashes f (of size bytes; an opened /proc/<pid>/exe reads
// through the kernel's link to the running image, so a binary deleted after
// exec still hashes), capped at maxBytes and budget.
func hashOpenFile(f *os.File, size, maxBytes int64, budget time.Duration) (string, error) {
	if size > maxBytes {
		return "", fmt.Errorf("%d bytes: %w", size, errExecHashTooLarge)
	}
	deadline := time.Now().Add(budget)
	sum := sha256.New()
	buf := make([]byte, 1<<20)
	var total int64
	for {
		if time.Now().After(deadline) {
			return "", errExecHashBudget
		}
		n, rerr := f.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > maxBytes {
				return "", errExecHashTooLarge
			}
			sum.Write(buf[:n])
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return "", rerr
		}
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
