package autosleep

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// fakeRow is a pgx.Row whose Scan writes a preset *time.Time into the
// caller's **time.Time destination (the shape LastNetworkActivity scans).
type fakeRow struct {
	val *time.Time
	err error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) == 1 {
		if p, ok := dest[0].(**time.Time); ok {
			*p = r.val
		}
	}
	return nil
}

// fakePool captures the SQL it was asked to run and returns a canned row.
type fakePool struct {
	gotSQL string
	row    pgx.Row
}

func (p *fakePool) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	p.gotSQL = sql
	return p.row
}

// TestLastNetworkActivity_OpenConnectionCountsAsNow pins #524's fix: the
// activity query must treat an OPEN connection (ended_at IS NULL) as
// active-now via now(), NOT fall back to started_at — otherwise a long SSH
// debug session looks idle and the box is slept mid-session. This guards the
// SQL so a refactor can't silently revert to the COALESCE(ended_at,
// started_at) form that had the bug.
func TestLastNetworkActivity_OpenConnectionCountsAsNow(t *testing.T) {
	p := &fakePool{row: fakeRow{val: nil}}
	a := &TrafficStoreAdapter{pool: p}
	if _, err := a.LastNetworkActivity(context.Background(), "alice-container"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(p.gotSQL, "ended_at IS NULL") || !strings.Contains(p.gotSQL, "now()") {
		t.Errorf("query must treat an open connection as now-active (CASE WHEN ended_at IS NULL THEN now()); got:\n%s", p.gotSQL)
	}
	if strings.Contains(p.gotSQL, "COALESCE(ended_at, started_at)") {
		t.Errorf("query regressed to the started_at fallback that sleeps active sessions (#524); got:\n%s", p.gotSQL)
	}
}

// TestLastNetworkActivity_ScansTime confirms a returned timestamp is passed
// through, and a NULL aggregate (no rows / all-null) maps to the zero time
// (the "no traffic ever" signal Decide special-cases).
func TestLastNetworkActivity_ScansTime(t *testing.T) {
	want := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	p := &fakePool{row: fakeRow{val: &want}}
	a := &TrafficStoreAdapter{pool: p}
	got, err := a.LastNetworkActivity(context.Background(), "alice-container")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("got %s, want %s", got, want)
	}

	// NULL aggregate → *time.Time nil → zero time.
	p2 := &fakePool{row: fakeRow{val: nil}}
	a2 := &TrafficStoreAdapter{pool: p2}
	got2, err := a2.LastNetworkActivity(context.Background(), "x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got2.IsZero() {
		t.Errorf("NULL aggregate should map to zero time, got %s", got2)
	}
}

// TestLastNetworkActivity_NilAdapter is the documented nil-receiver contract:
// a daemon without a traffic store returns zero time (no signal), so Decide
// falls back to its since-start branch rather than panicking.
func TestLastNetworkActivity_NilAdapter(t *testing.T) {
	var a *TrafficStoreAdapter
	got, err := a.LastNetworkActivity(context.Background(), "x")
	if err != nil || !got.IsZero() {
		t.Errorf("nil adapter: got (%v, %v), want (zero, nil)", got, err)
	}
}
