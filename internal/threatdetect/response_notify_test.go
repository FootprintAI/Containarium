//go:build integration

package threatdetect

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/events"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// responseNotifyStore is what the #2718 table drives: the write calls the
// process responder makes, on either store.
type responseNotifyStore interface {
	Upsert(ctx context.Context, f *Finding) (*Finding, error)
	SetResponse(ctx context.Context, id int64, r FindingResponse) (*Finding, error)
	SetResponseHeld(ctx context.Context, id int64, box, standing FindingResponse) (*Finding, error)
	ResolveWithResponse(ctx context.Context, id int64, r FindingResponse) (*Finding, error)
	Get(ctx context.Context, id int64) (*Finding, error)
	Resolve(ctx context.Context, id int64) (*Finding, error)
	SetNotifier(Notifier)
}

// #2718, through each store and the real WebhookNotifier gate, in the order
// the responder writes: the finding, then the response it applied, then its
// release. Every step is inside the re-notify interval, so only the response
// transitions can explain the extra deliveries.
func runResponseNotifyTable(t *testing.T, newStore func(t *testing.T) responseNotifyStore) {
	t.Helper()
	ctx := context.Background()
	throttle := pb.ProcessAction_PROCESS_ACTION_THROTTLE
	t0 := time.Unix(1_700_000_000, 0).UTC()

	type step struct {
		name  string
		do    func(s responseNotifyStore, id int64) (*Finding, error)
		want  int // deliveries this step adds
		state pb.ResponseState
	}
	upsert := func(s responseNotifyStore, _ int64) (*Finding, error) { return s.Upsert(ctx, sampleMemFinding()) }
	setResp := func(r FindingResponse) func(responseNotifyStore, int64) (*Finding, error) {
		return func(s responseNotifyStore, id int64) (*Finding, error) { return s.SetResponse(ctx, id, r) }
	}
	resolveWith := func(r FindingResponse) func(responseNotifyStore, int64) (*Finding, error) {
		return func(s responseNotifyStore, id int64) (*Finding, error) { return s.ResolveWithResponse(ctx, id, r) }
	}

	for _, tc := range []struct {
		name  string
		steps []step
	}{
		{"apply, repeats, operator release + resolve", []step{
			{"upsert", upsert, 1, pb.ResponseState_RESPONSE_STATE_UNSPECIFIED},
			{"responder applies", setResp(FindingResponse{Action: throttle, State: pb.ResponseState_RESPONSE_STATE_APPLIED, AppliedAt: t0}), 1, pb.ResponseState_RESPONSE_STATE_APPLIED},
			{"repeat upsert", upsert, 0, 0},
			{"repeat upsert again", upsert, 0, 0},
			{"operator release resolves the finding: one write, one delivery", resolveWith(FindingResponse{Action: throttle, State: pb.ResponseState_RESPONSE_STATE_RELEASED, AppliedAt: t0, ReleasedAt: t0.Add(time.Minute), ReleasedBy: ReleasedByOperator}), 1, pb.ResponseState_RESPONSE_STATE_RELEASED},
		}},
		{"actuator error", []step{
			{"upsert", upsert, 1, pb.ResponseState_RESPONSE_STATE_UNSPECIFIED},
			{"responder fails", setResp(FindingResponse{Action: throttle, State: pb.ResponseState_RESPONSE_STATE_FAILED, AppliedAt: t0, Error: "incus: boom"}), 1, pb.ResponseState_RESPONSE_STATE_FAILED},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			n := NewWebhookNotifier(newFakeConfigSource("http://127.0.0.1:1", ""), nil) // no worker: queue length = deliveries
			s.SetNotifier(n)
			var id int64
			for _, st := range tc.steps {
				f, err := st.do(s, id)
				if err != nil {
					t.Fatalf("%s: %v", st.name, err)
				}
				id = f.ID
				if got := len(n.queue); got != st.want {
					t.Fatalf("after %q: deliveries = %d, want %d", st.name, got, st.want)
				}
				if st.want == 1 {
					got := (<-n.queue).ToProto().GetResponse().GetState()
					if got != st.state {
						t.Errorf("after %q: delivered response = %s, want %s", st.name, got, st.state)
					}
				}
			}
		})
	}
}

func TestMemFindingStore_ResponseTransitionsAreDelivered(t *testing.T) {
	runResponseNotifyTable(t, func(t *testing.T) responseNotifyStore {
		auditStore, bus := memTestDeps(t)
		s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
		if err != nil {
			t.Fatalf("NewMemFindingStore: %v", err)
		}
		return s
	})
}

func TestFindingStore_ResponseTransitionsAreDelivered(t *testing.T) {
	runResponseNotifyTable(t, func(t *testing.T) responseNotifyStore {
		s, _, _ := newStores(t, threatdetectPool(t))
		return s
	})
}

// #2745 review: MemFindingStore.SetResponse queues a snapshot. A later write
// to the stored finding (the resolve an operator release makes next, or any
// caller holding the returned pointer) must not change what the queued
// delivery says.
func TestMemFindingStore_SetResponseNotifiesASnapshot(t *testing.T) {
	ctx := context.Background()
	auditStore, bus := memTestDeps(t)
	s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatalf("NewMemFindingStore: %v", err)
	}
	n := NewWebhookNotifier(newFakeConfigSource("http://127.0.0.1:1", ""), nil)
	s.SetNotifier(n)
	f, err := s.Upsert(ctx, sampleMemFinding())
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	<-n.queue
	stored, err := s.SetResponse(ctx, f.ID, FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE,
		State: pb.ResponseState_RESPONSE_STATE_RELEASED, ReleasedBy: ReleasedByOperator})
	if err != nil {
		t.Fatalf("SetResponse: %v", err)
	}
	// Mutate the stored finding after Notify.
	stored.State = FindingStateResolved
	stored.Count = 99
	stored.Response.State = pb.ResponseState_RESPONSE_STATE_FAILED
	stored.Response.Error = "mutated"

	queued := <-n.queue
	if queued.State != FindingStateOpen || queued.Count == 99 {
		t.Errorf("queued finding changed with the store: state=%s count=%d", queued.State, queued.Count)
	}
	if queued.Response.State != pb.ResponseState_RESPONSE_STATE_RELEASED || queued.Response.Error != "" {
		t.Errorf("queued response changed with the store: %+v", *queued.Response)
	}
}

// #2775: a kill delivered by SetResponse is a snapshot too; the pid and the
// skip reason on the queued response do not follow later writes to the stored
// finding.
func TestMemFindingStore_SetResponseNotifiesAKillSnapshot(t *testing.T) {
	ctx := context.Background()
	auditStore, bus := memTestDeps(t)
	s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatalf("NewMemFindingStore: %v", err)
	}
	n := NewWebhookNotifier(newFakeConfigSource("http://127.0.0.1:1", ""), nil)
	s.SetNotifier(n)
	f, err := s.Upsert(ctx, sampleMemFinding())
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	<-n.queue
	stored, err := s.SetResponse(ctx, f.ID, FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_ALERT,
		State: pb.ResponseState_RESPONSE_STATE_NONE, ProcessKilled: true, KilledPID: 4242})
	if err != nil {
		t.Fatalf("SetResponse: %v", err)
	}
	if len(n.queue) != 1 {
		t.Fatalf("kill under ALERT: deliveries = %d, want 1", len(n.queue))
	}
	stored.Response.KilledPID = 1
	stored.Response.KillSkipReason = pb.KillSkipReason_KILL_SKIP_REASON_OTHER
	queued := <-n.queue
	if queued.Response.KilledPID != 4242 || queued.Response.KillSkipReason != pb.KillSkipReason_KILL_SKIP_REASON_UNSPECIFIED || !queued.Response.ProcessKilled {
		t.Errorf("queued kill changed with the store: %+v", *queued.Response)
	}
}

// #2766 x #2775: a release from a box that killed nothing keeps the finding's
// whole kill on record (in the real SQL for the Postgres store, in memory for
// the other).
func runKeepKillTable(t *testing.T, s responseNotifyStore) {
	t.Helper()
	ctx := context.Background()
	f, err := s.Upsert(ctx, sampleMemFinding())
	if err != nil {
		t.Fatal(err)
	}
	alert := pb.ProcessAction_PROCESS_ACTION_ALERT
	if _, err := s.SetResponse(ctx, f.ID, FindingResponse{Action: alert, ProcessKilled: true, KilledPID: 22, Kills: 2,
		KillSkipReason: pb.KillSkipReason_KILL_SKIP_REASON_PID_REUSED}); err != nil {
		t.Fatal(err)
	}
	got, err := s.SetResponse(ctx, f.ID, FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE,
		State: pb.ResponseState_RESPONSE_STATE_RELEASED, ReleasedBy: ReleasedByOperator})
	if err != nil {
		t.Fatal(err)
	}
	r := got.Response
	if r.State != pb.ResponseState_RESPONSE_STATE_RELEASED || !r.ProcessKilled || r.KilledPID != 22 || r.Kills != 2 ||
		r.KillSkipReason != pb.KillSkipReason_KILL_SKIP_REASON_PID_REUSED {
		t.Fatalf("response after a no-kill release = %+v, want the finding's kill kept whole", r)
	}
}

func TestMemFindingStore_ReleaseKeepsTheKill(t *testing.T) {
	auditStore, bus := memTestDeps(t)
	s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatal(err)
	}
	runKeepKillTable(t, s)
}

func TestFindingStore_ReleaseKeepsTheKill(t *testing.T) {
	s, _, _ := newStores(t, threatdetectPool(t))
	runKeepKillTable(t, s)
}

// #2820, through each store and the real WebhookNotifier gate: two boxes of
// one tenant share a miner-signature finding under THROTTLE. The writes are
// the ones ProcessResponder makes. Each box's apply and release is delivered
// naming its box (response.container and the finding's container), the
// stored response never reads RELEASED while box B is still throttled, and
// B's release, the last, is one delivery that carries the resolve.
func runSharedFindingDeliveryTable(t *testing.T, s responseNotifyStore) {
	t.Helper()
	ctx := context.Background()
	n := NewWebhookNotifier(newFakeConfigSource("http://127.0.0.1:1", ""), nil) // no worker: queue length = deliveries
	s.SetNotifier(n)
	throttle := pb.ProcessAction_PROCESS_ACTION_THROTTLE
	t0 := time.Unix(1_700_000_000, 0).UTC()
	sig := func(box string) *Finding {
		return &Finding{Rule: pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE, Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH,
			TenantID: "acme", Container: box, Subject: "name:xmrig"}
	}
	applied := func(box string) FindingResponse {
		return FindingResponse{Action: throttle, State: pb.ResponseState_RESPONSE_STATE_APPLIED, AppliedAt: t0, ExpiresAt: t0.Add(time.Hour), Container: box}
	}
	releasedRec := func(box string) FindingResponse {
		return FindingResponse{Action: throttle, State: pb.ResponseState_RESPONSE_STATE_RELEASED, AppliedAt: t0, ExpiresAt: t0.Add(time.Hour),
			ReleasedAt: t0.Add(time.Minute), ReleasedBy: ReleasedByOperator, Container: box}
	}
	expect := func(step string, want int, box string, state pb.ResponseState, findingState pb.FindingState) {
		t.Helper()
		if got := len(n.queue); got != want {
			t.Fatalf("after %s: deliveries = %d, want %d", step, got, want)
		}
		if want == 0 {
			return
		}
		got := (<-n.queue).ToProto()
		if r := got.GetResponse(); r.GetState() != state || r.GetContainer() != box || got.GetContainer() != box || got.GetState() != findingState {
			t.Fatalf("after %s: delivered %s on response.container=%q container=%q (finding %s), want %s on %q (finding %s)",
				step, r.GetState(), r.GetContainer(), got.GetContainer(), got.GetState(), state, box, findingState)
		}
	}
	storedIs := func(step string, id int64, box string, state pb.ResponseState) {
		t.Helper()
		f, err := s.Get(ctx, id)
		if err != nil {
			t.Fatalf("after %s: get: %v", step, err)
		}
		if r := f.ToProto().GetResponse(); r.GetState() != state || r.GetContainer() != box {
			t.Fatalf("after %s: stored response %s on %q, want %s on %q", step, r.GetState(), r.GetContainer(), state, box)
		}
	}
	open := pb.FindingState_FINDING_STATE_OPEN

	f, err := s.Upsert(ctx, sig("box-a"))
	if err != nil {
		t.Fatal(err)
	}
	id := f.ID
	<-n.queue // the new finding
	if _, err := s.SetResponse(ctx, id, applied("box-a")); err != nil {
		t.Fatal(err)
	}
	expect("A applied", 1, "box-a", pb.ResponseState_RESPONSE_STATE_APPLIED, open)
	if _, err := s.Upsert(ctx, sig("box-b")); err != nil {
		t.Fatal(err)
	}
	expect("B's exec re-fires the shared finding", 0, "", 0, 0)
	if _, err := s.SetResponse(ctx, id, applied("box-b")); err != nil {
		t.Fatal(err)
	}
	expect("B applied", 1, "box-b", pb.ResponseState_RESPONSE_STATE_APPLIED, open)
	got, err := s.SetResponseHeld(ctx, id, releasedRec("box-a"), applied("box-b"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Response.State != pb.ResponseState_RESPONSE_STATE_APPLIED || got.Response.Container != "box-b" || got.State != FindingStateOpen {
		t.Fatalf("SetResponseHeld returned %s with response %+v, want open with box-b's APPLIED", got.State, *got.Response)
	}
	expect("A released while B holds", 1, "box-a", pb.ResponseState_RESPONSE_STATE_RELEASED, open)
	storedIs("A released while B holds", id, "box-b", pb.ResponseState_RESPONSE_STATE_APPLIED)
	if _, err := s.Upsert(ctx, sig("box-b")); err != nil {
		t.Fatal(err)
	}
	expect("a re-fire while B holds", 0, "", 0, 0)
	got, err = s.ResolveWithResponse(ctx, id, releasedRec("box-b"))
	if err != nil {
		t.Fatal(err)
	}
	if got.State != FindingStateResolved {
		t.Fatalf("ResolveWithResponse left the finding %s", got.State)
	}
	expect("B released, the last box", 1, "box-b", pb.ResponseState_RESPONSE_STATE_RELEASED, pb.FindingState_FINDING_STATE_RESOLVED)
	storedIs("B released, the last box", id, "box-b", pb.ResponseState_RESPONSE_STATE_RELEASED)

	// A finding already resolved (by hand) still gets the release recorded
	// and delivered, and says it was not open.
	got, err = s.ResolveWithResponse(ctx, id, releasedRec("box-c"))
	if !errors.Is(err, ErrFindingNotOpen) || got == nil {
		t.Fatalf("ResolveWithResponse on a resolved finding = %v, %v; want the finding and ErrFindingNotOpen", got, err)
	}
	expect("release on an already resolved finding", 1, "box-c", pb.ResponseState_RESPONSE_STATE_RELEASED, pb.FindingState_FINDING_STATE_RESOLVED)
	storedIs("release on an already resolved finding", id, "box-c", pb.ResponseState_RESPONSE_STATE_RELEASED)
	if _, err := s.ResolveWithResponse(ctx, id+1000, releasedRec("box-c")); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("ResolveWithResponse on a missing finding: %v, want ErrFindingNotFound", err)
	}
	if len(n.queue) != 0 {
		t.Fatalf("a missing finding delivered %d posts", len(n.queue))
	}
}

func TestMemFindingStore_SharedFindingDeliversEachBox(t *testing.T) {
	auditStore, bus := memTestDeps(t)
	s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatal(err)
	}
	runSharedFindingDeliveryTable(t, s)
}

func TestFindingStore_SharedFindingDeliversEachBox(t *testing.T) {
	s, _, _ := newStores(t, threatdetectPool(t))
	runSharedFindingDeliveryTable(t, s)
}

// #2820 x #2766: the kill on record stays sticky through the held write (on
// the stored standing record and on the delivered box record) and through
// the resolving write, in both stores.
func runKeepKillSharedTable(t *testing.T, s responseNotifyStore) {
	t.Helper()
	ctx := context.Background()
	n := NewWebhookNotifier(newFakeConfigSource("http://127.0.0.1:1", ""), nil)
	s.SetNotifier(n)
	f, err := s.Upsert(ctx, sampleMemFinding())
	if err != nil {
		t.Fatal(err)
	}
	<-n.queue
	throttle := pb.ProcessAction_PROCESS_ACTION_THROTTLE
	if _, err := s.SetResponse(ctx, f.ID, FindingResponse{Action: throttle, State: pb.ResponseState_RESPONSE_STATE_APPLIED,
		ProcessKilled: true, KilledPID: 22, Kills: 2, Container: "box-b"}); err != nil {
		t.Fatal(err)
	}
	<-n.queue
	killKept := func(step string, r *FindingResponse) {
		t.Helper()
		if !r.ProcessKilled || r.KilledPID != 22 || r.Kills != 2 {
			t.Fatalf("%s: response %+v, want the finding's kill (pid 22, kills 2) kept", step, *r)
		}
	}
	got, err := s.SetResponseHeld(ctx, f.ID,
		FindingResponse{Action: throttle, State: pb.ResponseState_RESPONSE_STATE_RELEASED, ReleasedBy: ReleasedByOperator, Container: "box-a"},
		FindingResponse{Action: throttle, State: pb.ResponseState_RESPONSE_STATE_APPLIED, Container: "box-b"})
	if err != nil {
		t.Fatal(err)
	}
	killKept("stored after the held write", got.Response)
	if len(n.queue) != 1 {
		t.Fatalf("held write: deliveries = %d, want 1", len(n.queue))
	}
	killKept("delivered by the held write", (<-n.queue).Response)
	got, err = s.ResolveWithResponse(ctx, f.ID, FindingResponse{Action: throttle, State: pb.ResponseState_RESPONSE_STATE_RELEASED,
		ReleasedBy: ReleasedByOperator, Container: "box-b"})
	if err != nil {
		t.Fatal(err)
	}
	killKept("stored after the resolving write", got.Response)
	killKept("delivered by the resolving write", (<-n.queue).Response)
}

func TestMemFindingStore_SharedWritesKeepTheKill(t *testing.T) {
	auditStore, bus := memTestDeps(t)
	s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatal(err)
	}
	runKeepKillSharedTable(t, s)
}

func TestFindingStore_SharedWritesKeepTheKill(t *testing.T) {
	s, _, _ := newStores(t, threatdetectPool(t))
	runKeepKillSharedTable(t, s)
}

// killStoreOp is which ResponseWriter call a step of the store sequence
// table makes.
type killStoreOp int

const (
	opSetResponse killStoreOp = iota
	opSetResponseHeld
	opResolveWithResponse
)

// killFactsOf is the kill facts a response carries, the part of it the
// stores keep sticky.
func killFactsOf(r *FindingResponse) killKey {
	if r == nil {
		return killKey{}
	}
	return killKey{r.ProcessKilled, r.KilledPID, r.Kills, r.KillSkipReason}
}

// #2816: one write sequence, both stores, identical kill facts. Every case
// runs against the in-memory store and the Postgres store (the real SQL),
// and each step's stored and delivered kill facts must match the expected
// value on both. Items 1 (a write carrying its own, newer kill), 4 (a no-kill
// write that carries a skip over a stored kill) and 6 (a stale kill, such as
// the release fallback's row pid with count 1, never overwrites a newer
// count).
func TestFindingStores_KillFactsAgreeOnEveryWriteSequence(t *testing.T) {
	ctx := context.Background()
	alert, throttle := pb.ProcessAction_PROCESS_ACTION_ALERT, pb.ProcessAction_PROCESS_ACTION_THROTTLE
	applied, released := pb.ResponseState_RESPONSE_STATE_APPLIED, pb.ResponseState_RESPONSE_STATE_RELEASED
	gone, reused := pb.KillSkipReason_KILL_SKIP_REASON_PROCESS_GONE, pb.KillSkipReason_KILL_SKIP_REASON_PID_REUSED
	kill := func(action pb.ProcessAction, state pb.ResponseState, pid, n uint32) FindingResponse {
		return FindingResponse{Action: action, State: state, ProcessKilled: true, KilledPID: pid, Kills: n}
	}
	noKill := func(state pb.ResponseState, skip pb.KillSkipReason) FindingResponse {
		return FindingResponse{Action: throttle, State: state, KillSkipReason: skip, ReleasedBy: ReleasedByOperator}
	}
	type step struct {
		op       killStoreOp
		r        FindingResponse // the write (SetResponse/ResolveWithResponse) or the box record (SetResponseHeld)
		standing FindingResponse // SetResponseHeld only
		want     killKey         // stored and delivered after this step
	}
	for _, tc := range []struct {
		name  string
		steps []step
	}{
		{"a stored kill, then a new kill: the new one wins (item 1)", []step{
			{op: opSetResponse, r: kill(alert, 0, 22, 2), want: killKey{true, 22, 2, 0}},
			{op: opSetResponse, r: kill(alert, 0, 33, 3), want: killKey{true, 33, 3, 0}},
		}},
		{"a stored kill, then a no-kill write carrying a skip: the kill on record is kept whole (item 4)", []step{
			{op: opSetResponse, r: kill(throttle, applied, 22, 2), want: killKey{true, 22, 2, 0}},
			{op: opSetResponse, r: noKill(released, gone), want: killKey{true, 22, 2, 0}},
		}},
		{"a stored kill with a skip, then a no-kill release keeps both", []step{
			{op: opSetResponse, r: func() FindingResponse { r := kill(alert, 0, 22, 2); r.KillSkipReason = reused; return r }(), want: killKey{true, 22, 2, reused}},
			{op: opSetResponse, r: noKill(released, 0), want: killKey{true, 22, 2, reused}},
		}},
		{"a stale kill never overwrites a newer count (item 6, release fallback)", []step{
			{op: opSetResponse, r: kill(throttle, applied, 33, 3), want: killKey{true, 33, 3, 0}},
			{op: opSetResponse, r: kill(throttle, released, 22, 1), want: killKey{true, 33, 3, 0}},
		}},
		{"a stale kill on a held write and on the resolving write", []step{
			{op: opSetResponse, r: kill(throttle, applied, 33, 3), want: killKey{true, 33, 3, 0}},
			{op: opSetResponseHeld, r: kill(throttle, released, 22, 1), standing: kill(throttle, applied, 22, 1), want: killKey{true, 33, 3, 0}},
			{op: opResolveWithResponse, r: kill(throttle, released, 22, 1), want: killKey{true, 33, 3, 0}},
		}},
		{"a skip with no kill on record is the writer's", []step{
			{op: opSetResponse, r: noKill(applied, gone), want: killKey{false, 0, 0, gone}},
			{op: opSetResponse, r: kill(throttle, applied, 44, 1), want: killKey{true, 44, 1, 0}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pg, auditStore, bus := newStores(t, threatdetectPool(t))
			mem, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range []struct {
				name  string
				store responseNotifyStore
			}{{"mem", mem}, {"postgres", pg}} {
				n := NewWebhookNotifier(newFakeConfigSource("http://127.0.0.1:1", ""), nil) // no worker: the queue holds every delivery
				s.store.SetNotifier(n)
				seed := sampleMemFinding()
				seed.Subject = tc.name
				f, err := s.store.Upsert(ctx, seed)
				if err != nil {
					t.Fatalf("%s: upsert: %v", s.name, err)
				}
				for len(n.queue) > 0 {
					<-n.queue
				}
				for i, st := range tc.steps {
					var got *Finding
					switch st.op {
					case opSetResponse:
						got, err = s.store.SetResponse(ctx, f.ID, st.r)
					case opSetResponseHeld:
						got, err = s.store.SetResponseHeld(ctx, f.ID, st.r, st.standing)
					case opResolveWithResponse:
						got, err = s.store.ResolveWithResponse(ctx, f.ID, st.r)
					}
					if err != nil {
						t.Fatalf("%s step %d: %v", s.name, i, err)
					}
					if k := killFactsOf(got.Response); k != st.want {
						t.Errorf("%s step %d: stored kill facts %+v, want %+v", s.name, i, k, st.want)
					}
					if reread, err := s.store.Get(ctx, f.ID); err != nil || killFactsOf(reread.Response) != st.want {
						t.Errorf("%s step %d: re-read kill facts %+v (err %v), want %+v", s.name, i, killFactsOf(reread.Response), err, st.want)
					}
					var delivered *Finding
					for len(n.queue) > 0 {
						delivered = <-n.queue
					}
					if delivered != nil && killFactsOf(delivered.Response) != st.want {
						t.Errorf("%s step %d: delivered kill facts %+v, want %+v", s.name, i, killFactsOf(delivered.Response), st.want)
					}
				}
			}
		})
	}
}
