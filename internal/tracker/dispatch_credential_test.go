package tracker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Credential resolution at each use (#2269): the dispatcher resolves the
// connection's broker credential through its CredentialSource at every
// forge call, never once per tick. RunEnded and the sweep can run up to
// the policy's run timeout after the tick that started the run; a
// rotated or short-lived credential resolved at that tick is stale by
// then. Real Postgres store, fake forge that records the credential each
// call carried, a credential source that rotates on every call.

const testCredentialSecret = "forge-token"

// rotatingCredentials returns a new value on every call — every
// resolution is a rotation — and can be rotated from outside (another
// consumer, or the secret being replaced) between calls.
type rotatingCredentials struct {
	mu   sync.Mutex
	n    int
	err  error
	asks []string // "tenant/secret" of every call
}

func (r *rotatingCredentials) BrokerCredential(_ context.Context, tenant, secretName string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asks = append(r.asks, tenant+"/"+secretName)
	if r.err != nil {
		return "", r.err
	}
	r.n++
	return fmt.Sprintf("cred-%d", r.n), nil
}

// rotate replaces the stored credential without anyone resolving it.
func (r *rotatingCredentials) rotate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
}

// current is the only value the forge still accepts.
func (r *rotatingCredentials) current() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return fmt.Sprintf("cred-%d", r.n)
}

func (r *rotatingCredentials) setErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

func (r *rotatingCredentials) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.asks...)
}

// forgeUse is one forge call and the credential it carried.
type forgeUse struct {
	op, cred, current string
}

// credRecordingProvider records the credential every forge call
// carries, alongside the value that was current at that moment.
type credRecordingProvider struct {
	*fakeDispatchProvider
	src  *rotatingCredentials
	mu   sync.Mutex
	uses []forgeUse
}

func (p *credRecordingProvider) record(op string, c Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.uses = append(p.uses, forgeUse{op: op, cred: c.Credential, current: p.src.current()})
}

func (p *credRecordingProvider) ListIssues(ctx context.Context, c Conn, f IssueFilter) ([]Issue, error) {
	p.record("ListIssues", c)
	return p.fakeDispatchProvider.ListIssues(ctx, c, f)
}

func (p *credRecordingProvider) GetIssue(ctx context.Context, c Conn, n int64) (Issue, error) {
	p.record("GetIssue", c)
	return p.fakeDispatchProvider.GetIssue(ctx, c, n)
}

func (p *credRecordingProvider) SetLabels(ctx context.Context, c Conn, n int64, add, remove []string) error {
	p.record(fmt.Sprintf("SetLabels+%v", add), c)
	return p.fakeDispatchProvider.SetLabels(ctx, c, n, add, remove)
}

func (p *credRecordingProvider) Comment(ctx context.Context, c Conn, n int64, body string) (Comment, error) {
	p.record("Comment", c)
	return p.fakeDispatchProvider.Comment(ctx, c, n, body)
}

// since returns the uses recorded from index i on.
func (p *credRecordingProvider) since(i int) []forgeUse {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]forgeUse(nil), p.uses[i:]...)
}

func (p *credRecordingProvider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.uses)
}

// credentialHarness builds one Dispatcher per tick, the way
// DispatchTrackerIssues does: the connection record is read and the
// credential resolved when the tick begins, then the dispatcher is
// handed the source to resolve it again at each use.
type credentialHarness struct {
	t        *testing.T
	store    *Store
	provider *credRecordingProvider
	src      *rotatingCredentials
	runs     *lifecycleRunStarter
	clock    *fakeClock
	leases   *fakeLeases
	user     string
}

func newCredentialHarness(t *testing.T, user string, issues ...Issue) (*credentialHarness, context.Context) {
	t.Helper()
	base, store, _, runs, ctx := newLifecycleFixture(t, user)
	src := &rotatingCredentials{}
	h := &credentialHarness{
		t: t, store: store, src: src, runs: runs, user: user,
		provider: &credRecordingProvider{fakeDispatchProvider: newFakeDispatchProvider(issues...), src: src},
		clock:    clockOf(t, base),
		leases:   newFakeLeases(),
	}
	return h, ctx
}

// dispatcher is the per-tick Dispatcher: Conn.Credential is the value
// resolved when the tick began.
func (h *credentialHarness) dispatcher(ctx context.Context) *Dispatcher {
	h.t.Helper()
	cred, err := h.src.BrokerCredential(ctx, h.user, testCredentialSecret)
	if err != nil {
		h.t.Fatalf("resolve tick credential: %v", err)
	}
	return &Dispatcher{
		Store:            h.store,
		Provider:         h.provider,
		Conn:             Conn{Project: "acme/widgets", Credential: cred},
		Credentials:      h.src,
		CredentialSecret: testCredentialSecret,
		Runs:             h.runs,
		Clock:            h.clock,
		Policy:           &Policy{RunTimeout: sweepTimeout},
		Leases:           h.leases,
	}
}

// assertEachUseCurrent fails for every forge call that carried a value
// other than the one current at that moment — a credential captured
// earlier and reused after a rotation.
func assertEachUseCurrent(t *testing.T, uses []forgeUse) {
	t.Helper()
	if len(uses) == 0 {
		t.Fatalf("no forge calls recorded")
	}
	for _, u := range uses {
		if u.cred != u.current {
			t.Errorf("%s used credential %q, want %q (resolved at the write, not reused from an earlier resolution)", u.op, u.cred, u.current)
		}
	}
}

// A run started in tick 1 and ended after tick 2 (each tick resolving
// its own credential) must write agent:done with the credential
// resolved at that write — not tick 1's.
func TestDispatchCredential_RunEndedResolvesAtWrite(t *testing.T) {
	const user = "tracker-cred-runended"
	h, ctx := newCredentialHarness(t, user, Issue{Number: 11, Labels: []string{"scope:product"}})

	d1 := h.dispatcher(ctx)
	tick1Cred := d1.Conn.Credential
	res, err := d1.Tick(ctx, user, "default")
	if err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick 1 = (%+v, %v), want one started", res, err)
	}
	h.leases.setLive(res.Started[0].RunID, true)
	assertEachUseCurrent(t, h.provider.since(0)) // queued + running writes

	// A later tick, its own credential resolved at its start; the run is
	// still going, so nothing is written for it.
	h.clock.Advance(30 * time.Minute)
	if res, err := h.dispatcher(ctx).Tick(ctx, user, "default"); err != nil || len(res.TimedOut) != 0 {
		t.Fatalf("Tick 2 = (%+v, %v), want nothing swept", res, err)
	}

	// The run ends through the lifecycle tick 1 handed the starter.
	h.clock.Advance(20 * time.Minute)
	mark := h.provider.count()
	h.runs.lifecycle(t, 0).RunEnded(ctx, RunOutcome{})

	ended := h.provider.since(mark)
	assertEachUseCurrent(t, ended)
	for _, u := range ended {
		if u.cred == tick1Cred {
			t.Errorf("%s reused tick 1's credential %q", u.op, tick1Cred)
		}
	}
	row := onlyRow(t, h.store, ctx, user)
	if row.State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE || row.LabelsPending {
		t.Fatalf("row = %+v, want DONE with labels landed", row)
	}
	if !containsString(h.provider.labels(11), LabelAgentDone) {
		t.Errorf("labels = %v, want %s", h.provider.labels(11), LabelAgentDone)
	}
	for _, ask := range h.src.calls() {
		if ask != user+"/"+testCredentialSecret {
			t.Errorf("credential resolved for %q, want %q", ask, user+"/"+testCredentialSecret)
		}
	}
}

// The sweep's projection — agent:failed and the failure comment — each
// resolve the credential at the write: a rotation while the swept run's
// lease is being ended must not leave the projection on the stale value
// the tick began with.
func TestDispatchCredential_SweepResolvesAtWrite(t *testing.T) {
	const user = "tracker-cred-sweep"
	h, ctx := newCredentialHarness(t, user, Issue{Number: 12, Labels: []string{"scope:product"}})

	res, err := h.dispatcher(ctx).Tick(ctx, user, "default")
	if err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick 1 = (%+v, %v), want one started", res, err)
	}
	h.leases.setLive(res.Started[0].RunID, true)
	h.leases.onEnd = func(string) { h.src.rotate() }

	h.clock.Advance(sweepTimeout + time.Second)
	d2 := h.dispatcher(ctx)
	mark := h.provider.count()
	res, err = d2.Tick(ctx, user, "default")
	if err != nil || len(res.TimedOut) != 1 {
		t.Fatalf("Tick 2 = (%+v, %v), want one timed out", res, err)
	}
	swept := h.provider.since(mark)
	assertEachUseCurrent(t, swept)
	var sawLabel, sawComment bool
	for _, u := range swept {
		sawLabel = sawLabel || u.op == fmt.Sprintf("SetLabels+%v", []string{LabelAgentFailed})
		sawComment = sawComment || u.op == "Comment"
		if u.cred == d2.Conn.Credential {
			t.Errorf("%s reused the credential resolved when the tick began", u.op)
		}
	}
	if !sawLabel || !sawComment {
		t.Fatalf("sweep forge calls = %+v, want the agent:failed label and the failure comment", swept)
	}
	if row := onlyRow(t, h.store, ctx, user); row.LabelsPending {
		t.Errorf("row = %+v, want labels landed", row)
	}
}

// A credential that cannot be resolved at the write is a forge write
// failure: the row still moves, and labels_pending records that the
// projection has not landed, for the next tick's retry (#2047, #2052).
func TestDispatchCredential_ResolveErrorLeavesLabelsPending(t *testing.T) {
	const user = "tracker-cred-error"
	h, ctx := newCredentialHarness(t, user, Issue{Number: 13, Labels: []string{"scope:product"}})

	res, err := h.dispatcher(ctx).Tick(ctx, user, "default")
	if err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick 1 = (%+v, %v), want one started", res, err)
	}
	h.leases.setLive(res.Started[0].RunID, true)

	h.src.setErr(errors.New("secret deleted"))
	mark := h.provider.count()
	h.runs.lifecycle(t, 0).RunEnded(ctx, RunOutcome{})
	if uses := h.provider.since(mark); len(uses) != 0 {
		t.Errorf("forge calls without a credential = %+v, want none", uses)
	}
	row := onlyRow(t, h.store, ctx, user)
	if row.State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE || !row.LabelsPending {
		t.Fatalf("row = %+v, want DONE with labels_pending", row)
	}

	// Resolvable again: the next tick's retry lands the projection with
	// the then-current credential.
	h.src.setErr(nil)
	mark = h.provider.count()
	if _, err := h.dispatcher(ctx).Tick(ctx, user, "default"); err != nil {
		t.Fatalf("Tick 2: %v", err)
	}
	assertEachUseCurrent(t, h.provider.since(mark))
	if row := onlyRow(t, h.store, ctx, user); row.LabelsPending {
		t.Errorf("row = %+v, want labels landed by the retry", row)
	}
	if !containsString(h.provider.labels(13), LabelAgentDone) {
		t.Errorf("labels = %v, want %s", h.provider.labels(13), LabelAgentDone)
	}
}
