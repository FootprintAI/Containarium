package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// #1706: the hash chain's root never leaves the database, so a Postgres-
// privileged operator can rewrite a row and recompute the chain forward
// undetectably. FileSink is the default external sink — an append-only
// file outside Postgres's reach — and AnchorManager is the periodic loop
// that keeps it current.

func tempSink(t *testing.T) *FileSink {
	t.Helper()
	path := filepath.Join(t.TempDir(), "anchors.jsonl")
	s, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	return s
}

func TestFileSink_EmptyFileNotPublished(t *testing.T) {
	s := tempSink(t)
	_, _, ok, err := s.LastPublished(context.Background())
	if err != nil {
		t.Fatalf("LastPublished: %v", err)
	}
	if ok {
		t.Fatal("ok = true for a sink that was never published to")
	}
}

func TestFileSink_PublishAndLastPublished(t *testing.T) {
	s := tempSink(t)
	ctx := context.Background()
	if err := s.PublishRoot(ctx, 10, "hash-at-10"); err != nil {
		t.Fatalf("PublishRoot: %v", err)
	}
	cp, root, ok, err := s.LastPublished(ctx)
	if err != nil {
		t.Fatalf("LastPublished: %v", err)
	}
	if !ok || cp != 10 || root != "hash-at-10" {
		t.Fatalf("LastPublished = (%d, %q, %v), want (10, %q, true)", cp, root, ok, "hash-at-10")
	}
}

func TestFileSink_AdvancesAcrossMultiplePublishes(t *testing.T) {
	s := tempSink(t)
	ctx := context.Background()
	if err := s.PublishRoot(ctx, 10, "hash-at-10"); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if err := s.PublishRoot(ctx, 20, "hash-at-20"); err != nil {
		t.Fatalf("second publish: %v", err)
	}
	cp, root, ok, err := s.LastPublished(ctx)
	if err != nil || !ok || cp != 20 || root != "hash-at-20" {
		t.Fatalf("LastPublished = (%d, %q, %v, %v), want (20, %q, true, nil)", cp, root, ok, err, "hash-at-20")
	}
}

// Republishing the exact same checkpoint+root is a no-op — the manager's
// own "skip if nothing new" check should make this rare, but the sink
// enforces it independently rather than trusting every future caller to
// get that right.
func TestFileSink_IdempotentRepublish(t *testing.T) {
	s := tempSink(t)
	ctx := context.Background()
	if err := s.PublishRoot(ctx, 10, "hash-at-10"); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := s.PublishRoot(ctx, 10, "hash-at-10"); err != nil {
		t.Fatalf("idempotent republish should not error: %v", err)
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatalf("read anchor file: %v", err)
	}
	if got := len(splitNonEmptyLines(string(data))); got != 1 {
		t.Errorf("anchor file has %d lines, want 1 — a duplicate publish should not grow it", got)
	}
}

// The whole point of anchoring: a checkpoint, once published, can never be
// silently replaced by a different root. This is the guard that makes the
// anchor trustworthy even if the daemon itself is later compromised and
// tries to re-anchor over its own history.
func TestFileSink_RejectsConflictingRoot(t *testing.T) {
	s := tempSink(t)
	ctx := context.Background()
	if err := s.PublishRoot(ctx, 10, "hash-at-10"); err != nil {
		t.Fatalf("first: %v", err)
	}
	err := s.PublishRoot(ctx, 10, "a-different-hash")
	if err == nil {
		t.Fatal("republishing checkpoint 10 with a different root succeeded — this defeats the anchor's purpose")
	}
	if !errors.Is(err, ErrAnchorConflict) {
		t.Errorf("err = %v, want ErrAnchorConflict", err)
	}
	// The conflicting write must not have landed.
	_, root, _, _ := s.LastPublished(ctx)
	if root != "hash-at-10" {
		t.Errorf("root = %q after a rejected conflicting publish, want the original", root)
	}
}

func TestFileSink_RejectsOlderCheckpoint(t *testing.T) {
	s := tempSink(t)
	ctx := context.Background()
	if err := s.PublishRoot(ctx, 20, "hash-at-20"); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := s.PublishRoot(ctx, 10, "hash-at-10"); err == nil {
		t.Fatal("publishing an older checkpoint after a newer one succeeded")
	}
}

// An append-only file can end mid-write after a crash. The last COMPLETE
// line is still the authoritative anchor; a truncated trailing line must
// not be mistaken for corruption of the whole history.
func TestFileSink_SkipsCorruptTrailingLine(t *testing.T) {
	s := tempSink(t)
	ctx := context.Background()
	if err := s.PublishRoot(ctx, 10, "hash-at-10"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open for corruption: %v", err)
	}
	if _, err := f.WriteString(`{"checkpoint":20,"root":"trunc`); err != nil {
		t.Fatalf("write partial line: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	cp, root, ok, err := s.LastPublished(ctx)
	if err != nil {
		t.Fatalf("LastPublished: %v", err)
	}
	if !ok || cp != 10 || root != "hash-at-10" {
		t.Fatalf("LastPublished = (%d, %q, %v), want the last GOOD record (10, %q, true)", cp, root, ok, "hash-at-10")
	}
}

func splitNonEmptyLines(s string) []string {
	var out []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// --- AnchorManager -----------------------------------------------------

type fakeChainStore struct {
	maxID     int64
	hashes    map[int64]string
	maxErr    error
	hashErr   error
	maxCalls  int
	hashCalls int
}

func (f *fakeChainStore) MaxRowID(context.Context) (int64, error) {
	f.maxCalls++
	if f.maxErr != nil {
		return 0, f.maxErr
	}
	return f.maxID, nil
}

func (f *fakeChainStore) RowHashAt(_ context.Context, id int64) (string, bool, error) {
	f.hashCalls++
	if f.hashErr != nil {
		return "", false, f.hashErr
	}
	h, ok := f.hashes[id]
	return h, ok, nil
}

type fakeSink struct {
	published []struct {
		checkpoint int64
		root       string
	}
	publishErr error
}

func (f *fakeSink) PublishRoot(_ context.Context, checkpoint int64, root string) error {
	if f.publishErr != nil {
		return f.publishErr
	}
	f.published = append(f.published, struct {
		checkpoint int64
		root       string
	}{checkpoint, root})
	return nil
}

func (f *fakeSink) LastPublished(context.Context) (int64, string, bool, error) {
	if len(f.published) == 0 {
		return 0, "", false, nil
	}
	last := f.published[len(f.published)-1]
	return last.checkpoint, last.root, true, nil
}

func TestAnchorManager_PublishesNewCheckpoint(t *testing.T) {
	store := &fakeChainStore{maxID: 42, hashes: map[int64]string{42: "root-42"}}
	sink := &fakeSink{}
	m := NewAnchorManager(store, sink, AnchorOptions{})
	m.tick(context.Background())

	if len(sink.published) != 1 {
		t.Fatalf("published %d times, want 1", len(sink.published))
	}
	if sink.published[0].checkpoint != 42 || sink.published[0].root != "root-42" {
		t.Errorf("published %+v, want checkpoint=42 root=root-42", sink.published[0])
	}
}

// The whole reason a tick is cheap between real anchors: no new rows means
// nothing to publish, so no sink write and no wasted round trip.
func TestAnchorManager_SkipsWhenNoNewRows(t *testing.T) {
	store := &fakeChainStore{maxID: 42, hashes: map[int64]string{42: "root-42"}}
	sink := &fakeSink{}
	m := NewAnchorManager(store, sink, AnchorOptions{})
	m.tick(context.Background())
	m.tick(context.Background())
	m.tick(context.Background())

	if len(sink.published) != 1 {
		t.Fatalf("published %d times across 3 ticks with no new rows, want 1", len(sink.published))
	}
}

func TestAnchorManager_PublishesAgainAfterNewRows(t *testing.T) {
	store := &fakeChainStore{maxID: 42, hashes: map[int64]string{42: "root-42", 50: "root-50"}}
	sink := &fakeSink{}
	m := NewAnchorManager(store, sink, AnchorOptions{})
	m.tick(context.Background())
	store.maxID = 50
	m.tick(context.Background())

	if len(sink.published) != 2 {
		t.Fatalf("published %d times, want 2", len(sink.published))
	}
	if sink.published[1].checkpoint != 50 {
		t.Errorf("second publish checkpoint = %d, want 50", sink.published[1].checkpoint)
	}
}

// An empty chain (nothing logged yet) has nothing to anchor — checkpoint 0
// isn't a real row and publishing it would be meaningless.
func TestAnchorManager_SkipsEmptyChain(t *testing.T) {
	store := &fakeChainStore{maxID: 0}
	sink := &fakeSink{}
	m := NewAnchorManager(store, sink, AnchorOptions{})
	m.tick(context.Background())

	if len(sink.published) != 0 {
		t.Fatalf("published %d times against an empty chain, want 0", len(sink.published))
	}
}

// A failed publish must not wedge the manager — the next tick tries again.
// This is the "loud, not fatal" half of #1706's "anchor failures are loud."
func TestAnchorManager_RetriesAfterSinkFailure(t *testing.T) {
	store := &fakeChainStore{maxID: 42, hashes: map[int64]string{42: "root-42"}}
	sink := &fakeSink{publishErr: errors.New("disk full")}
	m := NewAnchorManager(store, sink, AnchorOptions{})
	m.tick(context.Background())
	if len(sink.published) != 0 {
		t.Fatalf("published %d times despite the sink erroring, want 0", len(sink.published))
	}

	sink.publishErr = nil
	m.tick(context.Background())
	if len(sink.published) != 1 {
		t.Fatalf("published %d times after the sink recovered, want 1 — the manager must retry, not give up permanently", len(sink.published))
	}
}

func TestAnchorManager_StartStop(t *testing.T) {
	store := &fakeChainStore{maxID: 1, hashes: map[int64]string{1: "root-1"}}
	sink := &fakeSink{}
	fired := make(chan struct{}, 1)
	clock := time.Now
	m := NewAnchorManager(store, sink, AnchorOptions{Interval: time.Millisecond, Clock: clock})
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	go func() {
		for i := 0; i < 50; i++ {
			if len(sink.published) > 0 {
				fired <- struct{}{}
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("ticker never published within 2s")
	}
	cancel()
	m.Stop()
}
