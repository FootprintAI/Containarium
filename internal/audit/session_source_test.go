package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

// #1189 AC2: the collector abstraction is backend-neutral — no *incus.Client
// in the shared type, each backend supplying its own source.
//
// The test that matters is not "the interface exists" but that the collector
// produces correct audit records driven by a source with NOTHING incus about
// it — a different log format, a different reading strategy, and lines with
// no timestamp of their own.

// fakeSource is a session source with no incus in it at all.
type fakeSource struct {
	boxes    []SessionBox
	logs     map[string]string
	boxesErr error
	readErr  error
	parse    func(line string, year int, fallback time.Time) (time.Time, string, string, string, bool)
	reads    int
}

func (f *fakeSource) Boxes(context.Context) ([]SessionBox, error) {
	return f.boxes, f.boxesErr
}

func (f *fakeSource) ReadSessions(_ context.Context, box SessionBox) (string, error) {
	f.reads++
	if f.readErr != nil {
		return "", f.readErr
	}
	return f.logs[box.Name], nil
}

func (f *fakeSource) ParseLine(line string, year int, fallback time.Time) (time.Time, string, string, string, bool) {
	return f.parse(line, year, fallback)
}

// recordingStore captures what the collector wrote.
type recordingStore struct{ entries []*AuditEntry }

func (r *recordingStore) Log(_ context.Context, e *AuditEntry) error {
	r.entries = append(r.entries, e)
	return nil
}

func newAuditStore(t *testing.T) *recordingStore {
	t.Helper()
	return &recordingStore{}
}

// The collector drives a dropbear-shaped source end to end. Nothing here is
// incus, which is the whole point of the abstraction.
func TestCollector_WorksWithANonIncusSource(t *testing.T) {
	store := newAuditStore(t)
	src := &fakeSource{
		boxes: []SessionBox{{Name: "alice-box", Username: "alice"}},
		logs: map[string]string{
			"alice-box": `Mar 12 14:30:01 Pubkey auth succeeded for 'cld-alice' with ssh-ed25519 key SHA256:abc from 10.0.0.7:54321`,
		},
		parse: parseDropbearLine,
	}

	sc := NewSSHCollectorWithSource(src, store)
	sc.collectAll(context.Background())

	entries := store.entries
	if len(entries) != 1 {
		t.Fatalf("recorded %d entries, want 1 — a K8s box producing no records is "+
			"indistinguishable from one nobody logged into (#1189)", len(entries))
	}
	e := entries[0]
	if e.Action != "ssh_login" {
		t.Errorf("action = %q, want ssh_login so it is queryable identically to the LXC path", e.Action)
	}
	if e.Username != "alice" {
		t.Errorf("username = %q, want the box's tenant", e.Username)
	}
	if e.SourceIP != "10.0.0.7" {
		t.Errorf("source = %q, want the host without its port", e.SourceIP)
	}
	if e.ResourceID != "alice-box" {
		t.Errorf("resource = %q, want the box name", e.ResourceID)
	}
}

// The high-water mark is what stops every poll re-recording the same logins.
// It is shared logic, so it must work for any source.
func TestCollector_DoesNotReRecordSeenLogins(t *testing.T) {
	store := newAuditStore(t)
	src := &fakeSource{
		boxes: []SessionBox{{Name: "alice-box", Username: "alice"}},
		logs: map[string]string{
			"alice-box": `Mar 12 14:30:01 Pubkey auth succeeded for 'cld-alice' with ssh-ed25519 key SHA256:abc from 10.0.0.7:54321`,
		},
		parse: parseDropbearLine,
	}
	sc := NewSSHCollectorWithSource(src, store)

	sc.collectAll(context.Background())
	sc.collectAll(context.Background())
	sc.collectAll(context.Background())

	entries := store.entries
	if len(entries) != 1 {
		t.Errorf("recorded %d entries for one login across three polls — the audit trail would "+
			"grow without bound and every login would appear to happen repeatedly", len(entries))
	}
	if src.reads != 3 {
		t.Errorf("read the log %d times, want 3 — dedup must happen on the records, not by "+
			"skipping the read", src.reads)
	}
}

// A new login after the high-water mark is recorded.
func TestCollector_RecordsLoginsAfterTheHighWaterMark(t *testing.T) {
	store := newAuditStore(t)
	src := &fakeSource{
		boxes: []SessionBox{{Name: "alice-box", Username: "alice"}},
		logs: map[string]string{
			"alice-box": `Mar 12 14:30:01 Pubkey auth succeeded for 'a' with ssh-ed25519 key SHA256:x from 10.0.0.1:1`,
		},
		parse: parseDropbearLine,
	}
	sc := NewSSHCollectorWithSource(src, store)
	sc.collectAll(context.Background())

	src.logs["alice-box"] += "\n" +
		`Mar 12 15:00:00 Pubkey auth succeeded for 'a' with ssh-ed25519 key SHA256:x from 10.0.0.2:2`
	sc.collectAll(context.Background())

	entries := store.entries
	if len(entries) != 2 {
		t.Errorf("recorded %d entries, want 2 — a later login must not be swallowed by the "+
			"high-water mark", len(entries))
	}
}

// One box failing to read must not stop the others being collected.
func TestCollector_BoxReadFailureDoesNotStopOthers(t *testing.T) {
	store := newAuditStore(t)
	src := &fakeSource{
		boxes: []SessionBox{
			{Name: "broken", Username: "a"},
			{Name: "fine", Username: "b"},
		},
		logs:  map[string]string{},
		parse: parseDropbearLine,
	}
	// Fail only for the first box by making the read error unconditional and
	// then checking both were attempted.
	src.readErr = errors.New("pod is gone")

	sc := NewSSHCollectorWithSource(src, store)
	sc.collectAll(context.Background())

	if src.reads != 2 {
		t.Errorf("attempted %d reads, want both boxes — one unreadable box must not stop the "+
			"rest of the fleet being audited", src.reads)
	}
}

func TestCollector_BoxListFailureIsSurvivable(t *testing.T) {
	store := newAuditStore(t)
	src := &fakeSource{boxesErr: errors.New("apiserver down"), parse: parseDropbearLine}

	sc := NewSSHCollectorWithSource(src, store)
	sc.collectAll(context.Background()) // must not panic

	if entries := store.entries; len(entries) != 0 {
		t.Errorf("recorded %d entries despite being unable to list boxes", len(entries))
	}
}
