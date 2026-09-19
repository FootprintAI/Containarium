package tracker

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RunResolver answers "is this run still going" — backed by run
// leases (internal/runlease.Registry satisfies this). See its own
// doc comment for what its single-process, non-durable scope means
// for ClaimTrackerIssue's correctness.
type RunResolver interface {
	Live(runID string) bool
}

// Clock is the seam ClaimTrackerIssue reads the current time through,
// so a test can control what counts as "stale" without a real sleep.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production Clock.
var SystemClock Clock = systemClock{}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// DefaultStaleAfter is the design note's default: a claim marker from
// a run this daemon doesn't know about (e.g. made through another
// daemon instance) is still honored for this long before being
// considered abandoned and takeable.
const DefaultStaleAfter = 2 * time.Hour

// ClaimLocks serializes ClaimTrackerIssue calls per (username,
// connection, issue) within this daemon — the design note's "claims
// are serialized per (connection, issue) within the daemon." Callers
// must hold the lock for the full duration of one ClaimTrackerIssue
// call; the cross-daemon race that can still happen despite the lock
// (a different daemon instance racing this one) is what the
// post-claim re-read step guards against instead.
type ClaimLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// NewClaimLocks returns an empty ClaimLocks.
func NewClaimLocks() *ClaimLocks {
	return &ClaimLocks{locks: make(map[string]*sync.Mutex)}
}

// Lock returns the mutex for (username, connection, number), creating
// it on first use. Locks are never removed — a per-(tenant,
// connection, issue) mutex is a few dozen bytes and this daemon's
// tracker traffic is, per the architecture doc's own stated scale ("a
// handful of concurrent agent runs per tenant"), nowhere near where
// that adds up.
func (c *ClaimLocks) Lock(username, connection string, number int64) *sync.Mutex {
	key := fmt.Sprintf("%s/%s#%d", username, connection, number)
	c.mu.Lock()
	defer c.mu.Unlock()
	l, ok := c.locks[key]
	if !ok {
		l = &sync.Mutex{}
		c.locks[key] = l
	}
	return l
}

// ClaimResult is the outcome of ClaimTrackerIssue.
type ClaimResult struct {
	// Claimed is true when THIS run holds the claim once the call
	// returns — either it just claimed the issue, took over a stale
	// claim, or already held the claim (idempotent re-claim).
	Claimed bool
	// AlreadyClaimedByRunID is set when Claimed is false: the run id
	// that holds a live-or-fresh-enough claim instead.
	AlreadyClaimedByRunID string
	// Assigned is true if AssignIfUnassigned actually changed the
	// issue's assignee as part of this call.
	Assigned bool
}

// ClaimTrackerIssue implements the design note's claim algorithm.
// Callers must hold the ClaimLocks entry for (id's tenant, the
// connection, number) for the duration of this call — it assumes no
// other goroutine in this process is claiming the same issue
// concurrently; the cross-daemon case is handled by the re-read step
// below instead.
//
//  1. Read the issue's comments; find the newest kind=claim marker.
//     Absent, or from THIS run (id.RunID) → proceed to claim (a
//     same-run re-claim is idempotent: found and matching, nothing is
//     posted, this returns immediately with Claimed=true).
//  2. From a DIFFERENT run: if that run is resolver.Live, or its
//     marker is younger than staleAfter, return AlreadyClaimedByRunID
//     — no write. Otherwise it's stale and unowned; fall through.
//  3. Post the claim comment, then AssignIfUnassigned (never replaces
//     an existing assignee — correct on GitLab Free's single-assignee
//     model).
//  4. Re-read. If a foreign claim with a timestamp EARLIER than the
//     one just posted is now visible (a different daemon instance won
//     a race in the gap between this call's read and its post) and
//     that run is live-or-fresh, post a kind=yield comment (marking
//     THIS run's own just-posted claim as superseded — see
//     latestClaim) and report AlreadyClaimedByRunID instead of
//     Claimed.
//
// Every marker considered anywhere in this algorithm must also have
// been posted by the connection's OWN credential (resolved once via
// provider.WhoAmI) — caught in review of #1924 (CWE-345): the marker
// syntax is public and trivially reproducible by any tracker commenter,
// so trusting a marker's kind/run-id claims without checking who
// actually posted the comment would let anyone force a false
// ALREADY_CLAIMED. Every genuine claim/yield — even one made through a
// DIFFERENT daemon instance — shares this same identity, since every
// daemon for a given connection posts through the same one broker-only
// credential.
func ClaimTrackerIssue(ctx context.Context, provider WriterProvider, conn Conn, number int64, id Identity, resolver RunResolver, clock Clock, staleAfter time.Duration) (ClaimResult, error) {
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}

	brokerAuthor, err := provider.WhoAmI(ctx, conn)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("resolve broker identity: %w", err)
	}

	issue, err := provider.GetIssue(ctx, conn, number)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("read issue: %w", err)
	}

	if holder, when, found := latestClaim(issue.Comments, brokerAuthor); found {
		if holder == id.RunID {
			return ClaimResult{Claimed: true}, nil // idempotent re-claim
		}
		if resolver.Live(holder) || clock.Now().Sub(when) < staleAfter {
			return ClaimResult{AlreadyClaimedByRunID: holder}, nil
		}
		// Stale and not live: fall through and take over.
	}

	myClaim, err := provider.Comment(ctx, conn, number, Stamp(id, KindClaim))
	if err != nil {
		return ClaimResult{}, fmt.Errorf("post claim: %w", err)
	}

	assigned, err := provider.AssignIfUnassigned(ctx, conn, number)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("assign after claim: %w", err)
	}

	reread, err := provider.GetIssue(ctx, conn, number)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("re-read after claim: %w", err)
	}
	if holder, when, found := earliestForeignClaimBefore(reread.Comments, id.RunID, myClaim.CreatedAt, brokerAuthor); found {
		if resolver.Live(holder) || clock.Now().Sub(when) < staleAfter {
			// KindYield, not KindComment: this marks id.RunID's own
			// just-posted claim (above) as superseded, so a LATER call's
			// latestClaim scan — which otherwise finds the newest
			// kind=claim marker regardless of who actually won — never
			// mistakes this run's losing claim for the current holder.
			yield := fmt.Sprintf("Yielding to an earlier claim by %s.\n\n%s", holder, Stamp(id, KindYield))
			_, _ = provider.Comment(ctx, conn, number, yield) // best-effort
			return ClaimResult{AlreadyClaimedByRunID: holder}, nil
		}
	}

	return ClaimResult{Claimed: true, Assigned: assigned}, nil
}

// latestClaim scans comments (oldest-first, as both providers return
// them) for the newest kind=claim marker NOT superseded by that same
// run's own later kind=yield marker — considering ONLY comments
// authored by brokerAuthor (the connection's own credential identity;
// see ClaimTrackerIssue's doc comment on why unauthenticated markers
// must never be trusted).
//
// A losing run's claim comment is never retracted or edited — it stays
// in the comment history exactly as posted, chronologically AFTER the
// winning claim it lost to. Scanning purely for "newest kind=claim"
// would therefore hand a losing run's stale claim back as the current
// holder on every call after the race resolved (caught in review on
// #1924 — see docs/architecture/agent-tracker-broker.md's discussion).
// Scanning backward and tracking which run IDs have since posted a
// kind=yield skips exactly those superseded claims, so a run that lost
// a race is never mistaken for the holder again — including by itself,
// which is what makes its own idempotent re-claim check safe.
func latestClaim(comments []Comment, brokerAuthor string) (holder string, when time.Time, found bool) {
	voided := make(map[string]bool)
	for i := len(comments) - 1; i >= 0; i-- {
		if comments[i].Author != brokerAuthor {
			continue
		}
		runID, _, kind, ok := ParseMarker(comments[i].Body)
		if !ok {
			continue
		}
		switch kind {
		case KindYield:
			voided[runID] = true
		case KindClaim:
			if voided[runID] {
				continue
			}
			return runID, comments[i].CreatedAt, true
		}
	}
	return "", time.Time{}, false
}

// earliestForeignClaimBefore finds the first (oldest) kind=claim
// marker — authored by brokerAuthor, same reasoning as latestClaim —
// from a run other than myRunID whose comment predates "before" — the
// timestamp of the claim this call just posted. Used only by the
// post-claim re-read: a foreign claim satisfying this arrived in the
// race window between this call's initial read and its own post, and
// — being earlier — is the one that should win.
func earliestForeignClaimBefore(comments []Comment, myRunID string, before time.Time, brokerAuthor string) (holder string, when time.Time, found bool) {
	for _, c := range comments {
		if c.Author != brokerAuthor {
			continue
		}
		runID, _, kind, ok := ParseMarker(c.Body)
		if !ok || kind != KindClaim || runID == myRunID {
			continue
		}
		if c.CreatedAt.Before(before) {
			return runID, c.CreatedAt, true
		}
	}
	return "", time.Time{}, false
}
