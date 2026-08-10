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

// #1189 AC1/AC3: a K8s login must produce a record "equivalent in shape to
// the LXC path" and be "indistinguishable by consumer".
//
// Shape equivalence is the claim that is easy to believe and easy to get
// wrong — two sources, two log formats, two parsers, one record type. A
// consumer filtering on Action, or grouping by SourceIP, must not be able to
// tell which backend a record came from.
func TestCollector_BothBackendsProduceTheSameRecordShape(t *testing.T) {
	// An sshd line as the LXC path reads it.
	lxcStore := newAuditStore(t)
	lxcSrc := &fakeSource{
		boxes: []SessionBox{{Name: "alice-container", Username: "alice"}},
		logs: map[string]string{
			"alice-container": `Mar 12 14:30:01 host sshd[123]: Accepted publickey for alice from 10.0.0.7 port 54321 ssh2: ED25519 SHA256:abc`,
		},
		parse: func(line string, year int, _ time.Time) (time.Time, string, string, string, bool) {
			return parseAuthLogLine(line, year)
		},
	}
	NewSSHCollectorWithSource(lxcSrc, lxcStore).collectAll(context.Background())

	// The same login as the K8s path reads it: a stamped pod-log line.
	k8sStore := newAuditStore(t)
	k8sSrc := &fakeSource{
		boxes: []SessionBox{{Name: "alice", Username: "alice", Ref: "tenant-alice/alice-abc"}},
		logs: map[string]string{
			"alice": time.Date(2026, time.March, 12, 14, 30, 1, 0, time.UTC).Format(time.RFC3339Nano) +
				` Pubkey auth succeeded for 'alice' with ssh-ed25519 key SHA256:abc from 10.0.0.7:54321`,
		},
		parse: NewK8sSessionSource(nil, "").ParseLine,
	}
	NewSSHCollectorWithSource(k8sSrc, k8sStore).collectAll(context.Background())

	if len(lxcStore.entries) != 1 || len(k8sStore.entries) != 1 {
		t.Fatalf("recorded %d LXC and %d K8s entries, want one each",
			len(lxcStore.entries), len(k8sStore.entries))
	}
	lxc, k8s := lxcStore.entries[0], k8sStore.entries[0]

	// Action and principal come from the collector, not from either source,
	// so comparing them across backends could never fail. What is worth
	// pinning is the value itself: it is what a consumer filters on, and
	// changing it would break the query for both backends at once.
	for name, e := range map[string]*AuditEntry{"LXC": lxc, "K8s": k8s} {
		if e.Action != "ssh_login" {
			t.Errorf("%s action = %q, want ssh_login — the value /v1/audit/logs consumers "+
				"filter on", name, e.Action)
		}
		if e.Username != "alice" {
			t.Errorf("%s principal = %q, want the tenant", name, e.Username)
		}
	}
	// Source is what a consumer groups by. host:port on one side and host on
	// the other would split one client across two buckets.
	if lxc.SourceIP != k8s.SourceIP {
		t.Errorf("source differs by backend: %q vs %q — grouping by source would split one "+
			"client into two", lxc.SourceIP, k8s.SourceIP)
	}
	if !lxc.Timestamp.Equal(k8s.Timestamp) {
		t.Errorf("timestamp differs for the same login: %v vs %v", lxc.Timestamp, k8s.Timestamp)
	}
	// The box identifier is legitimately different — one names a container,
	// the other a tenant — but neither may be empty, or the record cannot say
	// which box was accessed.
	if lxc.ResourceID == "" || k8s.ResourceID == "" {
		t.Errorf("a record does not name its box: LXC %q, K8s %q", lxc.ResourceID, k8s.ResourceID)
	}
}
