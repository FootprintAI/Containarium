//go:build integration

package threatdetect

import (
	"context"
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
	resolve := func(s responseNotifyStore, id int64) (*Finding, error) { return s.Resolve(ctx, id) }

	for _, tc := range []struct {
		name  string
		steps []step
	}{
		{"apply, repeats, operator release + resolve", []step{
			{"upsert", upsert, 1, pb.ResponseState_RESPONSE_STATE_UNSPECIFIED},
			{"responder applies", setResp(FindingResponse{Action: throttle, State: pb.ResponseState_RESPONSE_STATE_APPLIED, AppliedAt: t0}), 1, pb.ResponseState_RESPONSE_STATE_APPLIED},
			{"repeat upsert", upsert, 0, 0},
			{"repeat upsert again", upsert, 0, 0},
			{"operator releases", setResp(FindingResponse{Action: throttle, State: pb.ResponseState_RESPONSE_STATE_RELEASED, AppliedAt: t0, ReleasedAt: t0.Add(time.Minute), ReleasedBy: ReleasedByOperator}), 1, pb.ResponseState_RESPONSE_STATE_RELEASED},
			{"release resolves the finding", resolve, 0, 0},
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
