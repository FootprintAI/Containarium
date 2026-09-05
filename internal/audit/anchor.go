package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// #1706 — anchoring the hash chain's root outside the database.
//
// hash_chain.go's own doc comment already named the gap: "Append-only
// forensics (push the chain root to an external sink periodically) detects
// deletions on top of this; that's tracked separately." This is that.
//
// The chain (hash_chain.go) is tamper-evident against an application-level
// attacker: editing a row breaks VerifyChain from that point forward. It is
// SILENT against a privileged one — an operator with Postgres write access
// can rewrite a row and recompute every hash after it, and internal
// consistency alone can't tell the difference between "untouched" and
// "tampered, then correctly recomputed." The only thing that can tell the
// difference is a copy of an old hash value held somewhere the rewriter
// doesn't control. That's what RootSink is for.
//
// Design choice: the default sink (FileSink) is a local append-only file,
// not an object-store upload or a co-signed timestamp (the issue's other
// two suggested shapes). It satisfies the THREAT MODEL AS STATED — "an
// operator with write access to Postgres" — since a Postgres credential
// grants no access to the daemon host's filesystem. It does not defend
// against a full host-root attacker (who could edit both); that is a
// materially larger threat model than #1706 asks for, and the RootSink
// interface is the seam a stronger backend (object-store-with-versioning,
// a remote co-signed timestamp service) would slot into without changing
// anything else — AnchorManager and VerifyChainAgainstAnchor talk to the
// interface, not the file.

// RootSink durably records the hash chain's current tip. Implementations
// MUST reject a call whose checkpoint was already published with a
// DIFFERENT root — accepting one would let a second, conflicting write
// silently replace the first, defeating the entire point of anchoring.
// Republishing the SAME (checkpoint, root) pair is a safe no-op.
type RootSink interface {
	// PublishRoot records that as of audit-log row id `checkpoint`, the
	// chain's row_hash was `root`.
	PublishRoot(ctx context.Context, checkpoint int64, root string) error
	// LastPublished returns the most recently published (checkpoint,
	// root), or ok=false if nothing has ever been published.
	LastPublished(ctx context.Context) (checkpoint int64, root string, ok bool, err error)
}

// ErrAnchorConflict is returned by PublishRoot when checkpoint was already
// published with a different root than the one now being published.
var ErrAnchorConflict = errors.New("audit: checkpoint already anchored with a different root")

// anchorRecord is FileSink's on-disk line shape: one JSON object per line,
// append-only. AnchoredAt is informational only (not part of what's
// verified) — it lets an operator eyeball how stale the last anchor is
// without decoding a hash.
type anchorRecord struct {
	Checkpoint int64  `json:"checkpoint"`
	Root       string `json:"root"`
	AnchoredAt string `json:"anchored_at"`
}

// FileSink is the default RootSink: an append-only local file, opened
// O_APPEND for every write so a partial write from a crash can only ever
// truncate the LAST line, never corrupt an earlier one. Read side skips a
// trailing line that doesn't parse, rather than treating it as evidence the
// whole file is compromised (see lastPublishedLocked).
type FileSink struct {
	path string
	mu   sync.Mutex
}

// NewFileSink builds a FileSink at path, creating its parent directory
// (0750) if needed. Does not create or touch the file itself — an absent
// file is a legitimate "never anchored yet" state (LastPublished reports
// ok=false), not an error.
func NewFileSink(path string) (*FileSink, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("audit: anchor file path required")
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("audit: create anchor directory %q: %w", dir, err)
		}
	}
	return &FileSink{path: path}, nil
}

func (f *FileSink) PublishRoot(_ context.Context, checkpoint int64, root string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	lastCheckpoint, lastRoot, ok, err := f.lastPublishedLocked()
	if err != nil {
		return err
	}
	if ok {
		switch {
		case checkpoint < lastCheckpoint:
			return fmt.Errorf("audit: refusing to anchor checkpoint %d, older than the last anchored checkpoint %d",
				checkpoint, lastCheckpoint)
		case checkpoint == lastCheckpoint:
			if root == lastRoot {
				return nil // idempotent — nothing to do
			}
			return fmt.Errorf("%w: checkpoint=%d", ErrAnchorConflict, checkpoint)
		}
	}

	rec := anchorRecord{Checkpoint: checkpoint, Root: root, AnchoredAt: time.Now().UTC().Format(time.RFC3339Nano)}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("audit: marshal anchor record: %w", err)
	}
	fh, err := os.OpenFile(f.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open anchor file: %w", err)
	}
	defer func() { _ = fh.Close() }()
	if _, err := fh.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: append anchor record: %w", err)
	}
	return nil
}

func (f *FileSink) LastPublished(_ context.Context) (int64, string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastPublishedLocked()
}

// lastPublishedLocked scans every line for the last one that parses as a
// valid anchorRecord. A truncated or corrupt trailing line — the only shape
// of damage an O_APPEND-only writer can produce from a crash mid-write — is
// skipped rather than failing the whole read: the write before it is still
// the authoritative last-known-good anchor, and losing that on a truncated
// tail would be strictly worse than ignoring one bad line.
func (f *FileSink) lastPublishedLocked() (int64, string, bool, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, fmt.Errorf("audit: read anchor file: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var rec anchorRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		return rec.Checkpoint, rec.Root, true, nil
	}
	return 0, "", false, nil
}

// ChainStore is the narrow slice of *Store the anchor manager needs, kept
// as an interface so unit tests fake it without a real Postgres — mirrors
// internal/ttlsweeper's IncusClient/Deleter seams.
type ChainStore interface {
	MaxRowID(ctx context.Context) (int64, error)
	RowHashAt(ctx context.Context, id int64) (hash string, found bool, err error)
}

// DefaultAnchorInterval is the tick cadence. This IS the exposure window
// the issue asks to have "stated and bounded": a privileged rewrite of a
// row anchored less than one interval ago is undetectable by
// VerifyChainAgainstAnchor until the NEXT tick publishes a newer
// checkpoint past it. 15 minutes bounds that window without anchoring on
// every single audit-log write, which would turn every write into two.
const DefaultAnchorInterval = 15 * time.Minute

// AnchorOptions bundles the optional knobs. Production callers should pass
// zero values to get DefaultAnchorInterval and time.Now.
type AnchorOptions struct {
	Interval time.Duration
	Clock    func() time.Time
}

// AnchorManager owns the tick loop that keeps a RootSink current. One
// Manager per daemon, alongside the other ticker managers (ttlsweeper,
// autosleep) — same Start(ctx)/Stop() lifecycle.
type AnchorManager struct {
	store ChainStore
	sink  RootSink

	interval time.Duration
	clock    func() time.Time

	stopCh   chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	// lastCheckpoint short-circuits a tick when nothing new has been
	// logged since the last successful publish. Touched only from the
	// single run goroutine's tick, so it needs no lock (mirrors
	// ttlsweeper.Manager.failures).
	lastCheckpoint int64
}

// NewAnchorManager constructs a manager. Neither store nor sink may be
// nil — an anchor manager with nowhere to read from or write to has
// nothing useful to do, and silently degrading would hide a wiring bug in
// daemon startup (same rationale as ttlsweeper.NewManager's panics).
func NewAnchorManager(store ChainStore, sink RootSink, opts AnchorOptions) *AnchorManager {
	if store == nil {
		panic("audit: nil ChainStore")
	}
	if sink == nil {
		panic("audit: nil RootSink")
	}
	if opts.Interval <= 0 {
		opts.Interval = DefaultAnchorInterval
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	return &AnchorManager{
		store:    store,
		sink:     sink,
		interval: opts.Interval,
		clock:    opts.Clock,
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start spawns the tick loop. Returns immediately.
func (m *AnchorManager) Start(ctx context.Context) {
	go m.run(ctx)
	log.Printf("[audit-anchor] ticker started (interval=%s) — a privileged rewrite is undetectable only within this window", m.interval)
}

// Stop signals the loop to exit and waits for it to finish. Idempotent.
func (m *AnchorManager) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
	<-m.done
}

func (m *AnchorManager) run(ctx context.Context) {
	defer close(m.done)
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-t.C:
			m.tick(ctx)
		}
	}
}

// tick publishes a new anchor at the chain's current tail, if the tail has
// advanced since the last successful publish. Every failure is logged
// loud and the loop continues — per #1706's "anchor failures are loud,"
// not "anchor failures are fatal": losing tamper-evidence against a
// privileged rewrite is bad, but taking the daemon down over a full disk
// is worse.
func (m *AnchorManager) tick(ctx context.Context) {
	id, err := m.store.MaxRowID(ctx)
	if err != nil {
		log.Printf("[audit-anchor] ERROR: read max row id: %v — anchor NOT updated, tamper-evidence against a privileged rewrite is degraded until the next successful tick", err)
		return
	}
	if id == 0 || id == m.lastCheckpoint {
		return // empty chain, or nothing new since the last anchor
	}
	root, found, err := m.store.RowHashAt(ctx, id)
	if err != nil {
		log.Printf("[audit-anchor] ERROR: read row hash at checkpoint %d: %v", id, err)
		return
	}
	if !found {
		// The row MaxRowID just reported no longer exists — a concurrent
		// delete raced us, or the table was truncated. Anchoring a
		// nonexistent checkpoint would be worse than not anchoring at all.
		log.Printf("[audit-anchor] ERROR: checkpoint %d reported by MaxRowID no longer exists in audit_logs", id)
		return
	}
	if err := m.sink.PublishRoot(ctx, id, root); err != nil {
		log.Printf("[audit-anchor] ERROR: publish anchor at checkpoint %d: %v — tamper-evidence against a privileged rewrite is degraded until this succeeds", id, err)
		return
	}
	m.lastCheckpoint = id
}
