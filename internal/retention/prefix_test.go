package retention

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const (
	gwClass   = pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS
	sessClass = pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS
)

// fakePrefix is a PrefixSource over a fixed answer. It records what it was
// asked and the order of its calls, to pin that nothing is removed before the
// audit entry exists.
type fakePrefix struct {
	count     PrefixCount
	countErr  error
	removal   PrefixRemoval
	removeErr error

	countCutoffs  map[pb.RetentionClass]time.Time
	removeCutoffs map[pb.RetentionClass]time.Time
	removeHeld    []string
	removeMax     int
	removed       int
	log           *[]string
}

func (f *fakePrefix) Store() string { return "audit_logs" }
func (f *fakePrefix) Classes() []pb.RetentionClass {
	return []pb.RetentionClass{gwClass, sessClass}
}
func (f *fakePrefix) CountPrefix(_ context.Context, c map[pb.RetentionClass]time.Time, _ []string) (PrefixCount, error) {
	f.countCutoffs = c
	return f.count, f.countErr
}
func (f *fakePrefix) RemovePrefix(_ context.Context, c map[pb.RetentionClass]time.Time, held []string, max int) (PrefixRemoval, error) {
	f.removed++
	f.removeCutoffs, f.removeHeld, f.removeMax = c, held, max
	if f.log != nil {
		*f.log = append(*f.log, "remove")
	}
	return f.removal, f.removeErr
}

func chainBase(id int64) *pb.RetentionChainBase {
	return &pb.RetentionChainBase{BaseId: id, BaseHash: "h", PurgedAt: timestamppb.New(fixedNow()), RowsPurged: id}
}

func eligibleChain() *fakePrefix {
	return &fakePrefix{
		count: PrefixCount{
			ByClass: map[pb.RetentionClass]Count{
				gwClass:   {Older: 9, Eligible: 7},
				sessClass: {Older: 4, Eligible: 3},
			},
			Base: chainBase(10),
			Note: "bounded by the anchor at id 500",
		},
		removal: PrefixRemoval{
			RemovedByClass: map[pb.RetentionClass]int64{gwClass: 7, sessClass: 3},
			Base:           chainBase(510),
		},
	}
}

func chainUnswept() []Unswept {
	return []Unswept{
		{Class: gwClass, Store: "audit_logs", Note: "not swept (#2878)"},
		{Class: sessClass, Store: "audit_logs", Note: "not swept (#2878)"},
		{Class: pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES, Store: "evidence_bundles", Note: "no store"},
	}
}

func TestPrefixSource_DryRunReportsEachClassAndNeverRemoves(t *testing.T) {
	p := eligibleChain()
	sw := newTestSweeper(t, NewMemoryStore(), nil, chainUnswept())
	sw.AddPrefixSource(p)

	rep, err := sw.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if p.removed != 0 {
		t.Fatalf("RemovePrefix called %d times in DRY_RUN, want never", p.removed)
	}
	gw := findStore(t, rep, gwClass, "audit_logs")
	if gw.GetStatus() != pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_COUNTED ||
		gw.GetOlderThanCutoff() != 9 || gw.GetEligible() != 7 || gw.GetHeld() != 2 || gw.GetRemoved() != 0 {
		t.Errorf("gateway-logs entry = %v, want COUNTED with 9 older, 7 eligible, 2 kept, 0 removed", gw)
	}
	if gw.GetChainBase().GetBaseId() != 10 || !strings.Contains(gw.GetNote(), "anchor at id 500") {
		t.Errorf("gateway-logs entry should carry the current base (10) and the bounding note, got %v", gw)
	}
	sess := findStore(t, rep, sessClass, "audit_logs")
	if sess.GetEligible() != 3 || sess.GetOlderThanCutoff() != 4 {
		t.Errorf("session entry = %v, want 4 older and 3 eligible", sess)
	}
	// Each class is counted against its own window.
	if want := fixedNow().AddDate(0, 0, -90); !p.countCutoffs[gwClass].Equal(want) || !p.countCutoffs[sessClass].Equal(want) {
		t.Errorf("cutoffs = %v, want both at the 90-day default %v", p.countCutoffs, want)
	}
	// The chained entries are no longer "not swept".
	for _, s := range rep.GetStores() {
		if s.GetStore() == "audit_logs" && s.GetStatus() == pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_NOT_SWEPT {
			t.Errorf("%v/audit_logs is still listed not swept: %v", s.GetClass(), s)
		}
	}
	if findStore(t, rep, pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES, "evidence_bundles").GetStatus() != pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_NOT_SWEPT {
		t.Error("evidence bundles must stay not swept")
	}
}

func TestPrefixSource_EnforceAuditsFirstThenRemovesAndReportsTheNewBase(t *testing.T) {
	var events []string
	p := eligibleChain()
	p.log = &events
	st := enforcing(t)
	if _, err := st.SetHold(context.Background(), "org-a", "case", "admin", nil); err != nil {
		t.Fatal(err)
	}
	sw := newTestSweeper(t, st, nil, chainUnswept())
	sw.SetAuditor(func(context.Context, *pb.RetentionReport) error { events = append(events, "audit"); return nil })
	sw.AddPrefixSource(p)

	rep, err := sw.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if strings.Join(events, ",") != "audit,remove" {
		t.Fatalf("events = %v, want the audit entry before the removal", events)
	}
	if p.removeMax != MaxRemovePerStore || strings.Join(p.removeHeld, ",") != "org-a" {
		t.Errorf("RemovePrefix got max=%d held=%v, want the bound and [org-a]", p.removeMax, p.removeHeld)
	}
	gw := findStore(t, rep, gwClass, "audit_logs")
	sess := findStore(t, rep, sessClass, "audit_logs")
	if gw.GetRemoved() != 7 || sess.GetRemoved() != 3 || !rep.GetEnforced() {
		t.Errorf("removed gw/sess = %d/%d enforced=%v, want 7/3/true", gw.GetRemoved(), sess.GetRemoved(), rep.GetEnforced())
	}
	if gw.GetChainBase().GetBaseId() != 510 || sess.GetChainBase().GetBaseId() != 510 {
		t.Errorf("both classes should report the new base 510, got %v / %v", gw.GetChainBase(), sess.GetChainBase())
	}
}

func TestPrefixSource_EnforceWithoutAnAuditorRemovesNothing(t *testing.T) {
	p := eligibleChain()
	sw := newTestSweeper(t, enforcing(t), nil, chainUnswept())
	sw.AddPrefixSource(p)

	if _, err := sw.Sweep(context.Background()); !errors.Is(err, ErrNoAuditor) {
		t.Fatalf("Sweep err = %v, want ErrNoAuditor", err)
	}
	if p.removed != 0 {
		t.Fatalf("RemovePrefix called %d times with no auditor, want never", p.removed)
	}
}

func TestPrefixSource_AFailedAuditWriteRemovesNothing(t *testing.T) {
	p := eligibleChain()
	sw := newTestSweeper(t, enforcing(t), nil, chainUnswept())
	sw.SetAuditor(func(context.Context, *pb.RetentionReport) error { return errors.New("audit down") })
	sw.AddPrefixSource(p)

	if _, err := sw.Sweep(context.Background()); err == nil {
		t.Fatal("Sweep succeeded although the audit write failed")
	}
	if p.removed != 0 {
		t.Fatalf("RemovePrefix called %d times after a failed audit write, want never", p.removed)
	}
}

func TestPrefixSource_NothingEligibleNeitherAuditsNorRemoves(t *testing.T) {
	p := eligibleChain()
	p.count.ByClass = map[pb.RetentionClass]Count{gwClass: {Older: 5}, sessClass: {Older: 0}}
	audited := 0
	sw := newTestSweeper(t, enforcing(t), nil, chainUnswept())
	sw.SetAuditor(func(context.Context, *pb.RetentionReport) error { audited++; return nil })
	sw.AddPrefixSource(p)

	if _, err := sw.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if audited != 0 || p.removed != 0 {
		t.Fatalf("audited %d, removed %d times with nothing eligible, want neither", audited, p.removed)
	}
}

func TestPrefixSource_APreviewNeverRemovesEvenInEnforceMode(t *testing.T) {
	p := eligibleChain()
	sw := newTestSweeper(t, enforcing(t), nil, chainUnswept())
	sw.SetAuditor(func(context.Context, *pb.RetentionReport) error { return nil })
	sw.AddPrefixSource(p)

	rep, err := sw.Preview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.removed != 0 || rep.GetEnforced() {
		t.Fatalf("Preview removed %d times, enforced=%v, want neither", p.removed, rep.GetEnforced())
	}
}

func TestPrefixSource_ACountFailureIsReportedAndNothingIsRemoved(t *testing.T) {
	p := eligibleChain()
	p.countErr = errors.New("count audit_logs: boom")
	sw := auditedSweeper(t, enforcing(t), nil, chainUnswept())
	sw.AddPrefixSource(p)

	rep, err := sw.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	for _, c := range []pb.RetentionClass{gwClass, sessClass} {
		got := findStore(t, rep, c, "audit_logs")
		if got.GetStatus() != pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_ERROR || !strings.Contains(got.GetNote(), "boom") {
			t.Errorf("%v entry = %v, want ERROR carrying the failure", c, got)
		}
	}
	if p.removed != 0 {
		t.Errorf("RemovePrefix called %d times after a failed count, want never", p.removed)
	}
}

func TestPrefixSource_ASkippedRemovalIsNotedNotSilent(t *testing.T) {
	p := eligibleChain()
	p.removal = PrefixRemoval{Skipped: "no anchor has been published, so nothing can be purged"}
	sw := auditedSweeper(t, enforcing(t), nil, chainUnswept())
	sw.AddPrefixSource(p)

	rep, err := sw.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := findStore(t, rep, gwClass, "audit_logs")
	if got.GetRemoved() != 0 || !strings.Contains(got.GetNote(), "not removed: no anchor") {
		t.Errorf("entry = %v, want 0 removed and the skip reason in the note", got)
	}
}

// zeroWindowStore reports a gateway-logs window of 0 days, which the policy
// store never stores; the sweeper still refuses to remove on it.
type zeroWindowStore struct{ Store }

func (z zeroWindowStore) GetPolicy(ctx context.Context) (*pb.RetentionPolicy, error) {
	p, err := z.Store.GetPolicy(ctx)
	if err != nil {
		return nil, err
	}
	for _, w := range p.GetWindows() {
		if w.GetClass() == gwClass {
			w.Days = 0
		}
	}
	return p, nil
}

func TestPrefixSource_AClassWithoutAWindowSkipsTheWholeStore(t *testing.T) {
	p := eligibleChain()
	sw := auditedSweeper(t, zeroWindowStore{enforcing(t)}, nil, chainUnswept())
	sw.AddPrefixSource(p)

	rep, err := sw.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.removed != 0 {
		t.Fatalf("RemovePrefix called %d times with a class that has no window, want never", p.removed)
	}
	if got := findStore(t, rep, sessClass, "audit_logs"); !strings.Contains(got.GetNote(), "no retention window") {
		t.Errorf("session entry = %v, want the whole store skipped for the missing window", got)
	}
}
