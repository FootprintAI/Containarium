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

const (
	// execHashMaxBytes caps the binary size hashed.
	execHashMaxBytes = 64 << 20
	// execHashBudget caps the wall time spent on one binary.
	execHashBudget = 200 * time.Millisecond
	// execHashQueue is the pending-request depth; a full queue drops the
	// request (counted) rather than blocking the exec path.
	execHashQueue = 64
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
	dropped  atomic.Uint64
	failed   atomic.Uint64
}

// newExecHasher builds a hasher that redelivers hashed events to deliver
// (the engine's OnExec). Run starts the worker.
func newExecHasher(deliver func(threatdetect.ExecEvent)) *execHasher {
	return &execHasher{
		procRoot: execProcRoot,
		maxBytes: execHashMaxBytes,
		budget:   execHashBudget,
		deliver:  deliver,
		queue:    make(chan threatdetect.ExecEvent, execHashQueue),
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
	sum, err := hashProcExe(h.procRoot, ev.PID, h.maxBytes, h.budget)
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

// hashProcExe returns the hex SHA-256 of /proc/<pid>/exe, read through the
// kernel's link to the running image (so a binary deleted after exec still
// hashes), capped at maxBytes and budget.
func hashProcExe(procRoot string, pid uint32, maxBytes int64, budget time.Duration) (string, error) {
	// #nosec G304 -- procRoot is a constant (or a test fixture) and pid a
	// number from the kernel's exec record.
	f, err := os.Open(filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10), "exe"))
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if st.Size() > maxBytes {
		return "", fmt.Errorf("%d bytes: %w", st.Size(), errExecHashTooLarge)
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
