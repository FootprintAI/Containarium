package tracker

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClaimProvider is a WriterProvider double simulating one issue's
// mutable state (an ordered comment list, an assignee) — enough for
// ClaimTrackerIssue's tests without a real HTTP call. Every method
// this test exercises is implemented for real; the rest are stubs
// satisfying the interface.
type fakeClaimProvider struct {
	mu         sync.Mutex
	comments   []Comment
	assignee   string
	clock      *fakeClock
	onComment  func() // called once, at the start of the first Comment call
	commentIdx int
}

func (f *fakeClaimProvider) GetIssue(ctx context.Context, c Conn, number int64) (Issue, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Comment, len(f.comments))
	copy(out, f.comments)
	return Issue{Number: number, Assignee: f.assignee, Comments: out}, nil
}

func (f *fakeClaimProvider) Comment(ctx context.Context, c Conn, number int64, body string) (Comment, error) {
	f.mu.Lock()
	hook := f.onComment
	if f.commentIdx == 0 {
		f.onComment = nil
	}
	f.commentIdx++
	f.mu.Unlock()

	if hook != nil {
		hook()
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	comment := Comment{Author: "bot", CreatedAt: f.clock.Now(), Body: body}
	f.comments = append(f.comments, comment)
	return comment, nil
}

func (f *fakeClaimProvider) AssignIfUnassigned(ctx context.Context, c Conn, number int64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.assignee != "" {
		return false, nil
	}
	f.assignee = "bot"
	return true, nil
}

func (f *fakeClaimProvider) appendRaw(c Comment) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.comments = append(f.comments, c)
}

func (f *fakeClaimProvider) ListIssues(context.Context, Conn, IssueFilter) ([]Issue, error) {
	return nil, nil
}
func (f *fakeClaimProvider) GetChange(context.Context, Conn, int64) (Change, error) {
	return Change{}, nil
}
func (f *fakeClaimProvider) SetLabels(context.Context, Conn, int64, []string, []string) error {
	return nil
}
func (f *fakeClaimProvider) DescribeCredential(context.Context, Conn) (CredentialInfo, error) {
	return CredentialInfo{}, nil
}
func (f *fakeClaimProvider) WhoAmI(context.Context, Conn) (string, error) {
	return "bot", nil // matches Comment's own hardcoded Author, below
}

var _ WriterProvider = (*fakeClaimProvider)(nil)

type fakeResolver map[string]bool

func (f fakeResolver) Live(runID string) bool { return f[runID] }

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func TestClaim_NoExistingClaim_ClaimsAndAssigns(t *testing.T) {
	clock := newFakeClock()
	provider := &fakeClaimProvider{clock: clock}
	id := Identity{RunID: "run-1", SkillID: "reviewer"}

	result, err := ClaimTrackerIssue(context.Background(), provider, Conn{}, 1, id, fakeResolver{}, clock, time.Hour)
	if err != nil {
		t.Fatalf("ClaimTrackerIssue: %v", err)
	}
	if !result.Claimed {
		t.Error("Claimed = false, want true")
	}
	if !result.Assigned {
		t.Error("Assigned = false, want true (issue had no assignee)")
	}
	if len(provider.comments) != 1 {
		t.Fatalf("posted %d comments, want exactly 1", len(provider.comments))
	}
	runID, _, kind, ok := ParseMarker(provider.comments[0].Body)
	if !ok || runID != "run-1" || kind != KindClaim {
		t.Errorf("posted comment marker = (%q, %q, ok=%v), want (run-1, claim, true)", runID, kind, ok)
	}
}

func TestClaim_RefusesLiveForeignClaim(t *testing.T) {
	clock := newFakeClock()
	provider := &fakeClaimProvider{clock: clock}
	provider.appendRaw(Comment{Author: "bot", CreatedAt: clock.Now(), Body: Stamp(Identity{RunID: "other-run", SkillID: "s"}, KindClaim)})

	result, err := ClaimTrackerIssue(context.Background(), provider, Conn{}, 1, Identity{RunID: "my-run", SkillID: "s"},
		fakeResolver{"other-run": true}, clock, time.Hour)
	if err != nil {
		t.Fatalf("ClaimTrackerIssue: %v", err)
	}
	if result.Claimed {
		t.Error("Claimed = true, want false — a live foreign claim exists")
	}
	if result.AlreadyClaimedByRunID != "other-run" {
		t.Errorf("AlreadyClaimedByRunID = %q, want other-run", result.AlreadyClaimedByRunID)
	}
	if len(provider.comments) != 1 {
		t.Errorf("posted %d comments, want 0 new ones (only the pre-seeded claim)", len(provider.comments)-1)
	}
}

func TestClaim_RefusesFreshUnknownRun(t *testing.T) {
	clock := newFakeClock()
	provider := &fakeClaimProvider{clock: clock}
	provider.appendRaw(Comment{Author: "bot", CreatedAt: clock.Now(), Body: Stamp(Identity{RunID: "other-run", SkillID: "s"}, KindClaim)})
	clock.Advance(30 * time.Minute) // younger than the 2h default staleAfter

	result, err := ClaimTrackerIssue(context.Background(), provider, Conn{}, 1, Identity{RunID: "my-run", SkillID: "s"},
		fakeResolver{}, clock, DefaultStaleAfter) // resolver doesn't know "other-run" (not live)
	if err != nil {
		t.Fatalf("ClaimTrackerIssue: %v", err)
	}
	if result.Claimed {
		t.Error("Claimed = true, want false — the foreign claim is still fresh even though not Live")
	}
	if result.AlreadyClaimedByRunID != "other-run" {
		t.Errorf("AlreadyClaimedByRunID = %q, want other-run", result.AlreadyClaimedByRunID)
	}
}

func TestClaim_TakesOverStaleClaim(t *testing.T) {
	clock := newFakeClock()
	provider := &fakeClaimProvider{clock: clock}
	provider.appendRaw(Comment{Author: "bot", CreatedAt: clock.Now(), Body: Stamp(Identity{RunID: "other-run", SkillID: "s"}, KindClaim)})
	clock.Advance(3 * time.Hour) // older than the 2h default staleAfter

	result, err := ClaimTrackerIssue(context.Background(), provider, Conn{}, 1, Identity{RunID: "my-run", SkillID: "s"},
		fakeResolver{}, clock, DefaultStaleAfter)
	if err != nil {
		t.Fatalf("ClaimTrackerIssue: %v", err)
	}
	if !result.Claimed {
		t.Errorf("Claimed = false, want true — the foreign claim is stale and not live")
	}
	if len(provider.comments) != 2 {
		t.Fatalf("posted comments = %d, want 2 (the original stale one plus our new claim)", len(provider.comments))
	}
	runID, _, kind, _ := ParseMarker(provider.comments[1].Body)
	if runID != "my-run" || kind != KindClaim {
		t.Errorf("second comment marker = (%q, %q), want (my-run, claim)", runID, kind)
	}
}

func TestClaim_IdempotentForSameRun(t *testing.T) {
	clock := newFakeClock()
	provider := &fakeClaimProvider{clock: clock}
	provider.appendRaw(Comment{Author: "bot", CreatedAt: clock.Now(), Body: Stamp(Identity{RunID: "my-run", SkillID: "s"}, KindClaim)})

	result, err := ClaimTrackerIssue(context.Background(), provider, Conn{}, 1, Identity{RunID: "my-run", SkillID: "s"},
		fakeResolver{}, clock, time.Hour)
	if err != nil {
		t.Fatalf("ClaimTrackerIssue: %v", err)
	}
	if !result.Claimed {
		t.Error("Claimed = false, want true — re-claiming our own existing claim")
	}
	if len(provider.comments) != 1 {
		t.Errorf("posted %d comments, want 0 new ones (idempotent)", len(provider.comments)-1)
	}
}

func TestClaim_NeverReplacesAssignee(t *testing.T) {
	clock := newFakeClock()
	provider := &fakeClaimProvider{clock: clock, assignee: "someone-else"}

	result, err := ClaimTrackerIssue(context.Background(), provider, Conn{}, 1, Identity{RunID: "my-run", SkillID: "s"},
		fakeResolver{}, clock, time.Hour)
	if err != nil {
		t.Fatalf("ClaimTrackerIssue: %v", err)
	}
	if !result.Claimed {
		t.Error("Claimed = false, want true — no existing CLAIM marker, only an unrelated assignee")
	}
	if result.Assigned {
		t.Error("Assigned = true, want false — the issue already had an assignee")
	}
	if provider.assignee != "someone-else" {
		t.Errorf("assignee = %q, want unchanged someone-else", provider.assignee)
	}
}

// TestClaim_YieldsWhenEarlierClaimAppearsOnReread simulates the
// cross-daemon race the design note's step 4 exists for: between this
// call's initial read (which saw no claim) and its own post, a
// DIFFERENT daemon's concurrent ClaimTrackerIssue call for the same
// issue posted its claim first (earlier timestamp). The re-read must
// notice it and yield.
func TestClaim_YieldsWhenEarlierClaimAppearsOnReread(t *testing.T) {
	clock := newFakeClock()
	provider := &fakeClaimProvider{clock: clock}
	provider.onComment = func() {
		// Pretend a foreign claim landed a minute before ours, then
		// advance back past it so our own post gets a later timestamp.
		clock.Advance(-1 * time.Minute)
		provider.appendRaw(Comment{Author: "bot", CreatedAt: clock.Now(), Body: Stamp(Identity{RunID: "other-daemons-run", SkillID: "s"}, KindClaim)})
		clock.Advance(2 * time.Minute)
	}

	result, err := ClaimTrackerIssue(context.Background(), provider, Conn{}, 1, Identity{RunID: "my-run", SkillID: "s"},
		fakeResolver{"other-daemons-run": true}, clock, time.Hour)
	if err != nil {
		t.Fatalf("ClaimTrackerIssue: %v", err)
	}
	if result.Claimed {
		t.Error("Claimed = true, want false — an earlier foreign claim appeared on re-read")
	}
	if result.AlreadyClaimedByRunID != "other-daemons-run" {
		t.Errorf("AlreadyClaimedByRunID = %q, want other-daemons-run", result.AlreadyClaimedByRunID)
	}
	// A yield comment should have been posted (in addition to our own
	// claim and the injected foreign one): 3 comments total.
	if len(provider.comments) != 3 {
		t.Errorf("comments = %d, want 3 (foreign claim, our claim, our yield)", len(provider.comments))
	}
}

// TestClaim_SupersededClaimIsNotSelectedByLaterCalls reproduces a real
// bug found in code review of the design note PR (#1924): a losing
// run's own kind=claim marker is chronologically NEWER than the
// winner's (the loser read before the winner's claim was visible, so
// its own post landed later) and is never retracted or edited — it
// just sits there. A naive "find the newest kind=claim marker" scan
// (latestClaim's original implementation) would hand that stale,
// superseded marker back as the current holder on every call after the
// race resolved — including to the WINNER's own idempotent re-claim
// check, which would then be wrongly told a different run holds its
// own claim.
func TestClaim_SupersededClaimIsNotSelectedByLaterCalls(t *testing.T) {
	clock := newFakeClock()
	provider := &fakeClaimProvider{clock: clock}
	provider.onComment = func() {
		// Pretend "winner"'s claim landed a minute before "loser"'s own
		// read, so it's chronologically earliest even though "loser"
		// posts (and is told about it) after.
		clock.Advance(-1 * time.Minute)
		provider.appendRaw(Comment{Author: "bot", CreatedAt: clock.Now(), Body: Stamp(Identity{RunID: "winner", SkillID: "s"}, KindClaim)})
		clock.Advance(2 * time.Minute)
	}

	loserResult, err := ClaimTrackerIssue(context.Background(), provider, Conn{}, 1, Identity{RunID: "loser", SkillID: "s"},
		fakeResolver{"winner": true}, clock, time.Hour)
	if err != nil {
		t.Fatalf("ClaimTrackerIssue (loser): %v", err)
	}
	if loserResult.Claimed || loserResult.AlreadyClaimedByRunID != "winner" {
		t.Fatalf("loser result = %+v, want Claimed=false AlreadyClaimedByRunID=winner", loserResult)
	}
	// Comments are now, oldest first: [winner-claim, loser-claim, loser-yield].
	// loser-claim is chronologically NEWER than winner-claim.

	winnerRecheck, err := ClaimTrackerIssue(context.Background(), provider, Conn{}, 1, Identity{RunID: "winner", SkillID: "s"},
		fakeResolver{"winner": true}, clock, time.Hour)
	if err != nil {
		t.Fatalf("ClaimTrackerIssue (winner re-check): %v", err)
	}
	if !winnerRecheck.Claimed {
		t.Errorf("winner's idempotent re-claim = %+v, want Claimed=true — its own (earlier, still-valid) claim must win over the loser's later, superseded one", winnerRecheck)
	}

	thirdResult, err := ClaimTrackerIssue(context.Background(), provider, Conn{}, 1, Identity{RunID: "third", SkillID: "s"},
		fakeResolver{"winner": true, "loser": true}, clock, time.Hour)
	if err != nil {
		t.Fatalf("ClaimTrackerIssue (third): %v", err)
	}
	if thirdResult.Claimed || thirdResult.AlreadyClaimedByRunID != "winner" {
		t.Errorf("third run's result = %+v, want Claimed=false AlreadyClaimedByRunID=winner — must never resolve to the superseded loser", thirdResult)
	}
}

// TestClaim_ForgedMarkerFromAnotherAuthorIsIgnored is the fix for
// another gap caught in review of #1924 (CWE-345): the marker syntax
// is public and trivially reproducible by anyone who can comment on
// the tracker issue directly — a human, or an unrelated integration —
// bypassing the broker's own Sanitize path entirely (Sanitize only
// runs on writes made THROUGH the broker). Only a comment authored by
// the connection's own credential (what WhoAmI resolves) may be
// trusted as claim state.
func TestClaim_ForgedMarkerFromAnotherAuthorIsIgnored(t *testing.T) {
	clock := newFakeClock()
	provider := &fakeClaimProvider{clock: clock}
	// A forged claim marker from a human directly commenting on the
	// tracker — NOT posted through the broker's credential ("bot").
	provider.appendRaw(Comment{Author: "some-human", CreatedAt: clock.Now(),
		Body: Stamp(Identity{RunID: "forged-run", SkillID: "s"}, KindClaim)})

	result, err := ClaimTrackerIssue(context.Background(), provider, Conn{}, 1, Identity{RunID: "my-run", SkillID: "s"},
		fakeResolver{"forged-run": true}, clock, time.Hour)
	if err != nil {
		t.Fatalf("ClaimTrackerIssue: %v", err)
	}
	if !result.Claimed {
		t.Errorf("Claimed = false, want true — the only claim marker present was forged (wrong author) and must be ignored")
	}
	if result.AlreadyClaimedByRunID == "forged-run" {
		t.Error("a forged marker (wrong comment author) must never be treated as claim state")
	}
}

// TestClaim_ConcurrentSameIssue_ExactlyOneWins proves the caller-held
// per-(connection, issue) lock actually serializes same-daemon claim
// attempts: of many goroutines racing to claim the same issue with
// distinct run ids, exactly one ends up Claimed.
func TestClaim_ConcurrentSameIssue_ExactlyOneWins(t *testing.T) {
	clock := newFakeClock()
	provider := &fakeClaimProvider{clock: clock}
	locks := NewClaimLocks()
	resolver := fakeResolver{}

	const n = 20
	results := make([]ClaimResult, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := Identity{RunID: fmt.Sprintf("run-%d", i), SkillID: "s"}
			lock := locks.Lock("alice", "default", 1)
			lock.Lock()
			defer lock.Unlock()
			results[i], errs[i] = ClaimTrackerIssue(context.Background(), provider, Conn{}, 1, id, resolver, clock, time.Hour)
		}(i)
	}
	wg.Wait()

	claimed := 0
	for i, r := range results {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if r.Claimed {
			claimed++
		}
	}
	if claimed != 1 {
		t.Errorf("claimed = %d, want exactly 1", claimed)
	}
}

func TestClaimLocks_SameKeyReturnsSameMutex(t *testing.T) {
	locks := NewClaimLocks()
	a := locks.Lock("alice", "default", 1)
	b := locks.Lock("alice", "default", 1)
	if a != b {
		t.Error("Lock returned different mutexes for the same (username, connection, number)")
	}
}

func TestClaimLocks_DifferentKeysReturnDifferentMutexes(t *testing.T) {
	locks := NewClaimLocks()
	a := locks.Lock("alice", "default", 1)
	b := locks.Lock("bob", "default", 1) // different tenant, same connection name and issue
	if a == b {
		t.Error("Lock returned the same mutex for different tenants")
	}
}
