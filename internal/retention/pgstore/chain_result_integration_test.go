//go:build integration

// Real-Postgres coverage for the entries a purge of the hash-chained audit_logs
// writes (#2979). The retention.sweep entry is written before the purge and can
// name only the chain base the purge starts from; the retention.sweep.result
// entry is written after and names the base it ended on. Both go through the
// real RetentionServer into a real audit store, and are read back from
// audit_logs, so what is checked is what an operator would find.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/retention/pgstore/
package pgstore_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/retention"
	"github.com/footprintai/containarium/internal/server"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const (
	sweepAction  = "retention.sweep"
	resultAction = "retention.sweep.result"
)

// sweepEntryDetail and resultEntryDetail read back the JSON the server writes.
type sweepEntryDetail struct {
	Stores []struct {
		Class          string `json:"class"`
		Store          string `json:"store"`
		PreviousBaseID int64  `json:"previous_base_id"`
	} `json:"stores"`
}

type resultEntryDetail struct {
	Store          string `json:"store"`
	PreviousBaseID int64  `json:"previous_base_id"`
	BaseID         int64  `json:"base_id"`
	RowsRemoved    int64  `json:"rows_removed"`
	Classes        []struct {
		Class   string `json:"class"`
		Removed int64  `json:"removed"`
	} `json:"classes"`
}

// refusing is an audit logger over the real store that refuses one action.
type refusing struct {
	*audit.Store
	action string
}

func (r refusing) Log(ctx context.Context, e *audit.AuditEntry) error {
	if e.Action == r.action {
		return errors.New("audit store refused " + e.Action)
	}
	return r.Store.Log(ctx, e)
}

// wireServer gives the env's sweeper the audit entries the daemon gives it: the
// real RetentionServer writing through logger.
func (e *chainEnv) wireServer(t *testing.T, logger interface {
	Log(context.Context, *audit.AuditEntry) error
}) {
	t.Helper()
	rs := server.NewRetentionServer(e.store)
	rs.SetAuditStore(logger)
	rs.SetReporter(retention.NewReporter(e.sweep))
}

// details returns the Detail of every entry with the action, oldest first.
func (e *chainEnv) details(t *testing.T, action string) []string {
	t.Helper()
	rows, err := e.pool.Query(e.ctx, `SELECT detail FROM audit_logs WHERE action = $1 ORDER BY id`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestChainResult_TheResultEntryNamesTheStoredBaseAndThePreviousOneAcrossTwoPurges(t *testing.T) {
	e := newChainEnv(t, expiredThenFresh())
	e.wireServer(t, e.audit)

	// First purge: rows 1..14 go, there was no base before.
	e.anchorAt(t, 15)
	e.enforce(t)
	first, ok, err := e.audit.ChainBase(e.ctx)
	if err != nil || !ok {
		t.Fatalf("no chain base after the first purge: ok=%v err=%v", ok, err)
	}

	// Second purge: rows 15..20 are expired and below the next anchor.
	e.anchorAt(t, 21)
	e.enforce(t)
	second, ok, err := e.audit.ChainBase(e.ctx)
	if err != nil || !ok || second.ID <= first.ID {
		t.Fatalf("chain base after the second purge = %+v (first %+v) ok=%v err=%v, want it moved forward", second, first, ok, err)
	}

	results := e.details(t, resultAction)
	if len(results) != 2 {
		t.Fatalf("got %d %s entries after two purges, want 2: %v", len(results), resultAction, results)
	}
	var r1, r2 resultEntryDetail
	if err := json.Unmarshal([]byte(results[0]), &r1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(results[1]), &r2); err != nil {
		t.Fatal(err)
	}
	if r1.Store != "audit_logs" || r1.PreviousBaseID != 0 || r1.BaseID != first.ID || r1.RowsRemoved != first.RowsPurged {
		t.Errorf("first result = %+v, want audit_logs, no previous base, base %d, %d rows", r1, first.ID, first.RowsPurged)
	}
	if r2.PreviousBaseID != first.ID || r2.BaseID != second.ID || r2.RowsRemoved != second.RowsPurged-first.RowsPurged {
		t.Errorf("second result = %+v, want previous base %d, stored base %d, %d rows", r2, first.ID, second.ID, second.RowsPurged-first.RowsPurged)
	}
	var byClass int64
	for _, c := range r2.Classes {
		byClass += c.Removed
	}
	if byClass != r2.RowsRemoved {
		t.Errorf("classes add up to %d rows, want rows_removed %d", byClass, r2.RowsRemoved)
	}

	// The entry written BEFORE each purge names the base that purge started from.
	sweeps := e.details(t, sweepAction)
	if len(sweeps) != 2 {
		t.Fatalf("got %d %s entries, want 2: %v", len(sweeps), sweepAction, sweeps)
	}
	var s1, s2 sweepEntryDetail
	if err := json.Unmarshal([]byte(sweeps[0]), &s1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(sweeps[1]), &s2); err != nil {
		t.Fatal(err)
	}
	for i, sd := range []sweepEntryDetail{s1, s2} {
		want := int64(0)
		if i == 1 {
			want = first.ID
		}
		seen := false
		for _, st := range sd.Stores {
			if st.Store != "audit_logs" {
				continue
			}
			seen = true
			if st.PreviousBaseID != want {
				t.Errorf("sweep entry %d: %s previous_base_id = %d, want %d", i+1, st.Class, st.PreviousBaseID, want)
			}
		}
		if !seen {
			t.Errorf("sweep entry %d names no audit_logs store: %s", i+1, sweeps[i])
		}
	}
	e.verify(t)
}

func TestChainResult_AFailedResultWriteLeavesThePurgeCommittedAndVerifying(t *testing.T) {
	e := newChainEnv(t, expiredThenFresh())
	e.wireServer(t, refusing{e.audit, resultAction})
	e.anchorAt(t, 15)

	rep := e.enforce(t) // fatals if the sweep returns an error

	min, _, _ := e.ids(t)
	if min != 15 {
		t.Fatalf("lowest remaining id is %d, want 15: the purge must stay committed", min)
	}
	base, ok, err := e.audit.ChainBase(e.ctx)
	if err != nil || !ok || base.ID != 14 {
		t.Fatalf("chain base = %+v ok=%v err=%v, want id 14", base, ok, err)
	}
	e.verify(t)
	if n := len(e.details(t, resultAction)); n != 0 {
		t.Errorf("%d %s entries although the store refused them", n, resultAction)
	}
	if n := len(e.details(t, sweepAction)); n != 1 {
		t.Errorf("%d %s entries, want the pre-delete entry", n, sweepAction)
	}
	gw := entry(t, rep, gwClass)
	if gw.GetRemoved() == 0 || gw.GetStatus() == pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_ERROR || !strings.Contains(gw.GetNote(), resultAction) {
		t.Errorf("gateway entry = removed %d status %v note %q, want the removal reported and the missing %s entry named",
			gw.GetRemoved(), gw.GetStatus(), gw.GetNote(), resultAction)
	}
}

func TestChainResult_NoResultEntryInDryRunOrWhenNothingWasPurged(t *testing.T) {
	t.Run("dry run", func(t *testing.T) {
		e := newChainEnv(t, expiredThenFresh())
		e.wireServer(t, e.audit)
		e.anchorAt(t, 15)

		if _, err := e.sweep.Sweep(e.ctx); err != nil { // the default mode is DRY_RUN
			t.Fatal(err)
		}
		if _, _, n := e.ids(t); n != 30 {
			t.Fatalf("a DRY_RUN sweep left %d rows, want all 30", n)
		}
		if a, b := len(e.details(t, sweepAction)), len(e.details(t, resultAction)); a != 0 || b != 0 {
			t.Fatalf("a dry run wrote %d %s and %d %s entries, want none", a, sweepAction, b, resultAction)
		}
	})
	t.Run("no anchor, nothing purged", func(t *testing.T) {
		e := newChainEnv(t, expiredThenFresh())
		e.wireServer(t, e.audit) // the anchor is left unset

		e.enforce(t)

		if _, _, n := e.ids(t); n != 30 {
			t.Fatalf("%d rows remain, want all 30 without an anchor", n)
		}
		if b := len(e.details(t, resultAction)); b != 0 {
			t.Fatalf("wrote %d %s entries although nothing was purged", b, resultAction)
		}
	})
}
