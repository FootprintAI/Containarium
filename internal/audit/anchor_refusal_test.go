package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"
)

// #3549: the chain behind the anchor file is a typed refusal, carrying both
// checkpoints, with the message operators already grep for.
func TestFileSink_OlderCheckpointIsAnchorBehindError(t *testing.T) {
	s := tempSink(t)
	ctx := context.Background()
	if err := s.PublishRoot(ctx, 1036, "hash-at-1036"); err != nil {
		t.Fatalf("first: %v", err)
	}
	err := s.PublishRoot(ctx, 106, "hash-at-106")
	var behind *AnchorBehindError
	if !errors.As(err, &behind) {
		t.Fatalf("err = %v (%T), want *AnchorBehindError", err, err)
	}
	if behind.Checkpoint != 106 || behind.LastAnchored != 1036 {
		t.Errorf("AnchorBehindError = %+v, want checkpoint 106, last anchored 1036", *behind)
	}
	if want := "audit: refusing to anchor checkpoint 106, older than the last anchored checkpoint 1036"; err.Error() != want {
		t.Errorf("message = %q, want %q", err.Error(), want)
	}
	// Through the tee the daemon uses when an external sink is configured.
	if err := NewTeeSink(s, &fakeSink{}).PublishRoot(ctx, 106, "hash-at-106"); !errors.As(err, &behind) {
		t.Errorf("tee err = %v, want it to still unwrap to *AnchorBehindError", err)
	}
}

// captureLog sends the standard logger to a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return &buf
}

// A chain recreated below the anchor file: every tick is refused and
// counted, the state is reported once when it starts with the explanation,
// and the next successful publish clears it and reports that once too.
func TestAnchorManager_ReportsAndClearsARefusingAnchor(t *testing.T) {
	logs := captureLog(t)
	sink := tempSink(t)
	ctx := context.Background()
	if err := sink.PublishRoot(ctx, 1036, "hash-at-1036"); err != nil {
		t.Fatal(err)
	}
	store := &fakeChainStore{maxID: 106, hashes: map[int64]string{106: "root-106", 1040: "root-1040"}}
	var changes []AnchorState
	m := NewAnchorManager(store, sink, AnchorOptions{OnStateChange: func(st AnchorState) { changes = append(changes, st) }})

	if st := m.State(); st.Refused || st.Refusals != 0 {
		t.Fatalf("before any tick: %+v, want not refused", st)
	}
	for range 3 {
		m.tick(ctx)
	}
	st := m.State()
	if !st.Refused || st.Checkpoint != 106 || st.LastAnchored != 1036 || st.Refusals != 3 {
		t.Fatalf("after 3 refused ticks: %+v, want refused at 106 behind 1036, 3 refusals", st)
	}
	if len(changes) != 1 || !changes[0].Refused || changes[0].Refusals != 1 {
		t.Fatalf("state changes = %+v, want one change to refused", changes)
	}
	out := logs.String()
	if n := strings.Count(out, "DEGRADED"); n != 1 {
		t.Errorf("explanation logged %d times over 3 refused ticks, want once:\n%s", n, out)
	}
	for _, want := range []string{"checkpoint 106, behind the anchor's last checkpoint 1036", "recreated or restored", "passes checkpoint 1036", "Keep the anchor file", "OPERATOR-SECURITY-RUNBOOK.md"} {
		if !strings.Contains(out, want) {
			t.Errorf("log does not say %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "ERROR: publish anchor at checkpoint 106"); n != 3 {
		t.Errorf("per-tick ERROR line logged %d times, want 3", n)
	}

	store.maxID = 1040
	m.tick(ctx)
	st = m.State()
	if st.Refused || st.Checkpoint != 0 || st.LastAnchored != 0 || st.Refusals != 3 {
		t.Fatalf("after a successful publish: %+v, want cleared with the 3 refusals kept", st)
	}
	if len(changes) != 2 || changes[1].Refused {
		t.Fatalf("state changes = %+v, want a second change back to anchoring", changes)
	}
	if !strings.Contains(logs.String(), "anchoring resumed: published checkpoint 1040") {
		t.Errorf("recovery not logged:\n%s", logs.String())
	}
	m.tick(ctx) // nothing new: no publish, no change
	if len(changes) != 2 {
		t.Errorf("state changes = %+v after an idle tick, want still 2", changes)
	}
}

// A checkpoint anchored with a different root is refused on every tick too.
func TestAnchorManager_ConflictIsARefusal(t *testing.T) {
	captureLog(t)
	sink := tempSink(t)
	ctx := context.Background()
	if err := sink.PublishRoot(ctx, 42, "root-anchored"); err != nil {
		t.Fatal(err)
	}
	store := &fakeChainStore{maxID: 42, hashes: map[int64]string{42: "root-rewritten"}}
	var changes []AnchorState
	m := NewAnchorManager(store, sink, AnchorOptions{OnStateChange: func(st AnchorState) { changes = append(changes, st) }})
	m.tick(ctx)
	m.tick(ctx)
	st := m.State()
	if !st.Refused || st.Checkpoint != 42 || st.LastAnchored != 0 || st.Refusals != 2 {
		t.Fatalf("state = %+v, want refused at 42 (a conflict), 2 refusals", st)
	}
	if len(changes) != 1 {
		t.Errorf("state changes = %+v, want one", changes)
	}
}

// A failure that may pass on its own is not a refusal: it is logged per tick
// as before and leaves the state alone, in both directions.
func TestAnchorManager_TransientFailureIsNotARefusal(t *testing.T) {
	captureLog(t)
	ctx := context.Background()
	store := &fakeChainStore{maxID: 42, hashes: map[int64]string{42: "root-42"}}
	sink := &fakeSink{publishErr: errors.New("disk full")}
	var changes []AnchorState
	m := NewAnchorManager(store, sink, AnchorOptions{OnStateChange: func(st AnchorState) { changes = append(changes, st) }})
	m.tick(ctx)
	if st := m.State(); st.Refused || st.Refusals != 0 || len(changes) != 0 {
		t.Fatalf("after a transient failure: %+v, changes %+v; want untouched", st, changes)
	}

	// Refused first, then a transient failure: still refused, not counted.
	sink.publishErr = fmt.Errorf("local anchor file (external anchor skipped): %w", &AnchorBehindError{Checkpoint: 42, LastAnchored: 50})
	m.tick(ctx)
	sink.publishErr = errors.New("disk full")
	m.tick(ctx)
	if st := m.State(); !st.Refused || st.Refusals != 1 || len(changes) != 1 {
		t.Fatalf("refused then transient: %+v, changes %+v; want still refused, 1 refusal", st, changes)
	}
	store.maxErr = errors.New("connection refused")
	m.tick(ctx)
	if st := m.State(); !st.Refused || st.Refusals != 1 {
		t.Fatalf("after an unreadable chain: %+v, want still refused", st)
	}
}
