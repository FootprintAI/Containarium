package retention

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Count is what one store holds past a cutoff.
type Count struct {
	// Older is every record older than the cutoff, held or not.
	Older int64
	// Eligible is the part of Older that no legal hold keeps.
	Eligible int64
}

// Unattributed is the Count of a store whose records carry no org. While any
// hold is active such a record counts as held (Q21 on #2727): the sweeper
// cannot tell whose it is, so it keeps it.
func Unattributed(older int64, heldOrgs []string) Count {
	if len(heldOrgs) > 0 {
		return Count{Older: older}
	}
	return Count{Older: older, Eligible: older}
}

// Source counts one store's records of one class. It has no delete: a count
// must never be able to remove anything, so enforcement (#2877) is the
// separate Remover interface that a source may also implement.
type Source interface {
	Class() pb.RetentionClass
	// Store names the store in the report, such as a table name.
	Store() string
	// Count counts the records older than cutoff. heldOrgs are the orgs with
	// an active legal hold, ordered by org id; a store with no org column
	// returns Unattributed.
	Count(ctx context.Context, cutoff time.Time, heldOrgs []string) (Count, error)
}

// MaxRemovePerStore bounds how many records one sweep removes from one store.
// A backlog larger than this is worked off over the following sweeps, so a
// first enforced sweep over years of data cannot hold the database for long.
const MaxRemovePerStore = 100_000

// Remover deletes the records a Source counts as eligible. The cutoff and the
// held orgs are the ones Count takes, and Remove must apply the same
// predicate, so a sweep deletes exactly what its report listed: records older
// than the cutoff that no legal hold keeps. It removes at most maxRows and
// returns how many it removed.
type Remover interface {
	Remove(ctx context.Context, cutoff time.Time, heldOrgs []string, maxRows int) (Removal, error)
}

// Removal is what one Remove did.
type Removal struct {
	Removed int64
	// Skipped says why a store could not be swept at all (a table that does not
	// exist, so no hold could be ruled out), so a silent zero is not mistaken
	// for "nothing to remove".
	Skipped string
}

// Auditor records an enforced sweep before anything is removed. The report it
// receives carries the per-class, per-store counts and never record content.
// Its error stops the sweep: nothing is removed without its audit entry.
type Auditor func(ctx context.Context, rep *pb.RetentionReport) error

// Unswept is a store the sweeper lists but does not count, with why.
type Unswept struct {
	Class pb.RetentionClass
	Store string
	Note  string
}

// ChainAndBundles lists the classes the dry-run sweeper does not count: the
// hash-chained audit_logs classes (slice D, #2878) and evidence bundles
// (slice E, #2879; no bundle store exists yet).
func ChainAndBundles() []Unswept {
	const chained = "in the hash-chained audit_logs: only the oldest rows below the latest anchor can be removed, with a stored chain base; handled by #2878"
	return []Unswept{
		{Class: pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS, Store: "audit_logs", Note: chained},
		{Class: pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS, Store: "audit_logs", Note: chained},
		{Class: pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES, Store: "evidence_bundles",
			Note: "no evidence-bundle store exists yet; handled by #2879 once the Proof Pack store lands (#2366)"},
	}
}

// Sweeper turns the policy, the holds and the sources into a report. In
// DRY_RUN mode, and for a Preview in any mode, it reads only; in ENFORCE mode
// Sweep also removes what the report lists as eligible.
type Sweeper struct {
	store   Store
	sources []Source
	unswept []Unswept
	audit   Auditor
	now     func() time.Time
}

// SetAuditor wires the audit entry an enforced sweep writes. With none, an
// enforced sweep writes no entry (no audit store on this daemon).
func (s *Sweeper) SetAuditor(a Auditor) { s.audit = a }

func NewSweeper(store Store, sources []Source, unswept []Unswept) *Sweeper {
	return &Sweeper{store: store, sources: sources, unswept: unswept, now: time.Now}
}

// Sweep counts every source against its class window and, when the mode is
// ENFORCE, removes the eligible records. A source that fails is reported ERROR
// and the rest are still swept; a failure to read the policy, the mode or the
// holds, or to write the audit entry of an enforced sweep, fails the sweep
// before anything is removed.
func (s *Sweeper) Sweep(ctx context.Context) (*pb.RetentionReport, error) { return s.run(ctx, true) }

// Preview counts like Sweep and never removes, whatever the mode: the report
// is how an admin sees what the next enforced sweep will do.
func (s *Sweeper) Preview(ctx context.Context) (*pb.RetentionReport, error) {
	return s.run(ctx, false)
}

// counted pairs a report entry with the source and cutoff behind it.
type counted struct {
	entry  *pb.RetentionStoreReport
	src    Source
	cutoff time.Time
}

func (s *Sweeper) run(ctx context.Context, mayRemove bool) (*pb.RetentionReport, error) {
	policy, err := s.store.GetPolicy(ctx)
	if err != nil {
		return nil, fmt.Errorf("read retention policy: %w", err)
	}
	modeState, err := s.store.GetMode(ctx)
	if err != nil {
		return nil, fmt.Errorf("read retention mode: %w", err)
	}
	holds, err := s.store.ListHolds(ctx)
	if err != nil {
		return nil, fmt.Errorf("read legal holds: %w", err)
	}
	heldOrgs := make([]string, len(holds))
	for i, h := range holds {
		heldOrgs[i] = h.GetOrgId()
	}
	sort.Strings(heldOrgs)
	days := make(map[pb.RetentionClass]int32, len(policy.GetWindows()))
	for _, w := range policy.GetWindows() {
		days[w.GetClass()] = w.GetDays()
	}

	now := s.now()
	rep := &pb.RetentionReport{
		Mode:           modeState.GetMode(),
		GeneratedAt:    timestamppb.New(now),
		PolicyRevision: policy.GetRevision(),
		ActiveHolds:    int64(len(holds)),
	}
	var swept []counted
	for _, src := range s.sources {
		d := days[src.Class()]
		cutoff := now.AddDate(0, 0, -int(d))
		entry := &pb.RetentionStoreReport{
			Class:      src.Class(),
			Store:      src.Store(),
			Status:     pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_COUNTED,
			WindowDays: d,
			Cutoff:     timestamppb.New(cutoff),
		}
		c, err := src.Count(ctx, cutoff, heldOrgs)
		if err != nil {
			entry.Status = pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_ERROR
			entry.Note = err.Error()
		} else {
			entry.OlderThanCutoff, entry.Eligible, entry.Held = c.Older, c.Eligible, c.Older-c.Eligible
		}
		rep.Stores = append(rep.Stores, entry)
		swept = append(swept, counted{entry: entry, src: src, cutoff: cutoff})
	}
	for _, u := range s.unswept {
		rep.Stores = append(rep.Stores, &pb.RetentionStoreReport{
			Class:      u.Class,
			Store:      u.Store,
			Status:     pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_NOT_SWEPT,
			WindowDays: days[u.Class],
			Note:       u.Note,
		})
	}
	sort.SliceStable(rep.Stores, func(i, j int) bool {
		a, b := rep.Stores[i], rep.Stores[j]
		if a.GetClass() != b.GetClass() {
			return a.GetClass() < b.GetClass()
		}
		return a.GetStore() < b.GetStore()
	})
	if mayRemove && modeState.GetMode() == pb.RetentionMode_RETENTION_MODE_ENFORCE {
		if err := s.enforce(ctx, rep, swept, heldOrgs); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

// ErrNoAuditor is returned by an enforced sweep on a daemon with no audit
// store: removing data with no record of it is refused.
var ErrNoAuditor = errors.New("enforce mode needs an audit store (Postgres with REST enabled and a started audit store); nothing removed")

// enforce audits the sweep and then removes, store by store. A store shared by
// two classes (a crew run holds a prompt and a response) is removed once, with
// the longer of its classes' windows, so neither class loses a record early.
// It fails closed: with no auditor, or when the audit write fails, nothing is
// removed; with nothing eligible it neither audits nor removes.
func (s *Sweeper) enforce(ctx context.Context, rep *pb.RetentionReport, swept []counted, heldOrgs []string) error {
	var order []string
	byStore := map[string][]counted{}
	var eligible int64
	for _, c := range swept {
		if _, ok := c.src.(Remover); !ok {
			continue
		}
		if _, seen := byStore[c.src.Store()]; !seen {
			order = append(order, c.src.Store())
		}
		byStore[c.src.Store()] = append(byStore[c.src.Store()], c)
		if c.entry.GetStatus() == pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_COUNTED {
			eligible += c.entry.GetEligible()
		}
	}
	if s.audit == nil {
		return ErrNoAuditor
	}
	rep.Enforced = true
	if eligible == 0 {
		return nil // nothing to remove, so nothing to record
	}
	if err := s.audit(ctx, rep); err != nil {
		rep.Enforced = false
		return fmt.Errorf("audit the enforced sweep (nothing removed): %w", err)
	}

	for _, store := range order {
		group := byStore[store]
		decider := group[0]
		skip := ""
		for _, c := range group {
			if c.entry.GetStatus() != pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_COUNTED {
				skip = "not removed: counting this store failed"
			}
			if c.entry.GetWindowDays() < 1 {
				skip = "not removed: the class has no retention window"
			}
			if c.entry.GetWindowDays() > decider.entry.GetWindowDays() {
				decider = c
			}
		}
		if len(group) > 1 {
			note := fmt.Sprintf("a row is removed once past the longer window of its classes (%v, %d days)",
				decider.entry.GetClass(), decider.entry.GetWindowDays())
			for _, c := range group {
				if c != decider {
					c.entry.Note = note
				}
			}
		}
		if skip != "" {
			for _, c := range group {
				c.entry.Note = skip
			}
			continue
		}
		res, err := decider.src.(Remover).Remove(ctx, decider.cutoff, heldOrgs, MaxRemovePerStore)
		// res.Removed rows may have gone before a failure; report them.
		decider.entry.Removed = res.Removed
		switch {
		case err != nil:
			for _, c := range group {
				c.entry.Status = pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_ERROR
				c.entry.Note = err.Error()
			}
		case res.Skipped != "":
			for _, c := range group {
				c.entry.Note = "not removed: " + res.Skipped
			}
		}
	}
	return nil
}

// Reporter keeps the last report of a Sweeper and sweeps on a ticker.
type Reporter struct {
	sweeper *Sweeper

	sweepMu sync.Mutex // one sweep at a time
	mu      sync.RWMutex
	last    *pb.RetentionReport
}

func NewReporter(s *Sweeper) *Reporter { return &Reporter{sweeper: s} }

// SetAuditor wires the audit entry of an enforced sweep (see Sweeper.SetAuditor).
func (r *Reporter) SetAuditor(a Auditor) { r.sweeper.SetAuditor(a) }

// Last returns the kept report, nil before the first sweep.
func (r *Reporter) Last() *pb.RetentionReport {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.last
}

// sweep runs the periodic sweep, which removes in ENFORCE mode, and keeps its
// report.
func (r *Reporter) sweep(ctx context.Context) (*pb.RetentionReport, error) {
	r.sweepMu.Lock()
	defer r.sweepMu.Unlock()
	rep, err := r.sweeper.Sweep(ctx)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.last = rep
	r.mu.Unlock()
	return rep, nil
}

// preview counts without removing. Its report is kept unless the kept one is an
// enforced sweep's, which is the evidence of what was removed.
func (r *Reporter) preview(ctx context.Context) (*pb.RetentionReport, error) {
	r.sweepMu.Lock()
	defer r.sweepMu.Unlock()
	rep, err := r.sweeper.Preview(ctx)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.last == nil || !r.last.GetEnforced() {
		r.last = rep
	}
	r.mu.Unlock()
	return rep, nil
}

// Report returns the kept report; it runs a count-only preview first when
// refresh is set or no sweep has run yet. A read never removes records.
func (r *Reporter) Report(ctx context.Context, refresh bool) (*pb.RetentionReport, error) {
	if !refresh {
		if last := r.Last(); last != nil {
			return last, nil
		}
	}
	return r.preview(ctx)
}

// Run sweeps once at start and then every interval until ctx is done. A failed
// sweep is logged and retried on the next tick; the previous report stays.
func (r *Reporter) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := r.sweep(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[retention] sweep failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
