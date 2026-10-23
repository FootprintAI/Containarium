package retention

import (
	"context"
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

// Source counts one store's records of one class. It has no delete: the
// dry-run sweeper (#2876) must not be able to remove anything, and enforcement
// (#2877) adds its own interface instead of widening this one.
type Source interface {
	Class() pb.RetentionClass
	// Store names the store in the report, such as a table name.
	Store() string
	// Count counts the records older than cutoff. heldOrgs are the orgs with
	// an active legal hold, ordered by org id; a store with no org column
	// returns Unattributed.
	Count(ctx context.Context, cutoff time.Time, heldOrgs []string) (Count, error)
}

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

// Sweeper turns the policy, the holds and the sources into a report. It reads
// only.
type Sweeper struct {
	store   Store
	sources []Source
	unswept []Unswept
	now     func() time.Time
}

func NewSweeper(store Store, sources []Source, unswept []Unswept) *Sweeper {
	return &Sweeper{store: store, sources: sources, unswept: unswept, now: time.Now}
}

// Sweep counts every source against its class window. A source that fails is
// reported ERROR and the rest are still counted; only a failure to read the
// policy or the holds fails the sweep.
func (s *Sweeper) Sweep(ctx context.Context) (*pb.RetentionReport, error) {
	policy, err := s.store.GetPolicy(ctx)
	if err != nil {
		return nil, fmt.Errorf("read retention policy: %w", err)
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
		Mode:           pb.RetentionMode_RETENTION_MODE_DRY_RUN,
		GeneratedAt:    timestamppb.New(now),
		PolicyRevision: policy.GetRevision(),
		ActiveHolds:    int64(len(holds)),
	}
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
	return rep, nil
}

// Reporter keeps the last report of a Sweeper and sweeps on a ticker.
type Reporter struct {
	sweeper *Sweeper

	sweepMu sync.Mutex // one sweep at a time
	mu      sync.RWMutex
	last    *pb.RetentionReport
}

func NewReporter(s *Sweeper) *Reporter { return &Reporter{sweeper: s} }

// Last returns the kept report, nil before the first sweep.
func (r *Reporter) Last() *pb.RetentionReport {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.last
}

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

// Report returns the kept report; it sweeps first when refresh is set or no
// sweep has run yet.
func (r *Reporter) Report(ctx context.Context, refresh bool) (*pb.RetentionReport, error) {
	if !refresh {
		if last := r.Last(); last != nil {
			return last, nil
		}
	}
	return r.sweep(ctx)
}

// Run sweeps once at start and then every interval until ctx is done. A failed
// sweep is logged and retried on the next tick; the previous report stays.
func (r *Reporter) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := r.sweep(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[retention] dry-run sweep failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
