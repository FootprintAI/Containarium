package alert

import (
	"context"
	"errors"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"testing"
	"time"
)

type episodeProber struct {
	*fakeProber
	observation  CredentialEpisodes
	ackErr       error
	acknowledged []string
}

func (p *episodeProber) CredentialEpisodes(context.Context, CredentialWatchTarget) (CredentialEpisodes, error) {
	return p.observation, nil
}
func (p *episodeProber) AcknowledgeCredentialEpisodes(_ context.Context, _ CredentialWatchTarget, ids []string) error {
	if p.ackErr != nil {
		return p.ackErr
	}
	p.acknowledged = append(p.acknowledged, ids...)
	acknowledged := map[string]bool{}
	for _, id := range ids {
		acknowledged[id] = true
	}
	var pending []CredentialEpisode
	for _, e := range p.observation.Pending {
		if !acknowledged[e.ID] {
			pending = append(pending, e)
		}
	}
	p.observation.Pending = pending
	return nil
}
func testEpisodeDelivery(t *testing.T, store CredentialStateStore) {
	t.Helper()
	ctx := context.Background()
	p := &episodeProber{fakeProber: oneTargetProber(srcInteractive)}
	n := &recordingNotifier{}
	watcher := NewCredentialWatcher(p, store, n)
	watcher.Sweep(ctx)
	// Failure and recovery between sweeps, plus another failure/recovery. Both
	// episodes must notify even though current status is already healthy.
	p.observation = CredentialEpisodes{Version: 1, Pending: []CredentialEpisode{{ID: "00000000-0000-0000-0000-000000000001"}, {ID: "00000000-0000-0000-0000-000000000002", AfterRecovery: true}}}
	p.ackErr = errors.New("guest unavailable")
	if got := watcher.Sweep(ctx); got != 2 {
		t.Fatalf("alerts=%d want=2", got)
	}
	if len(p.acknowledged) != 0 {
		t.Fatal("acknowledged failed guest write")
	}
	// Simulates restart after DB commits, but before guest acknowledgement.
	watcher = NewCredentialWatcher(p, store, n)
	p.ackErr = nil
	if got := watcher.Sweep(ctx); got != 0 {
		t.Fatalf("restart repeated %d alerts", got)
	}
	if n.count() != 2 || len(p.acknowledged) != 2 {
		t.Fatalf("notifications=%d acknowledgements=%d", n.count(), len(p.acknowledged))
	}
	if got := watcher.Sweep(ctx); got != 0 {
		t.Fatal("recovery notified")
	}
}
func TestCredentialEpisodeDelivery(t *testing.T) { testEpisodeDelivery(t, newMemStateStore()) }
func TestCredentialEpisodesPersistBeforeAck(t *testing.T) {
	store := newMemStateStore()
	store.recordErr = errors.New("database down")
	p := &episodeProber{fakeProber: oneTargetProber(srcInteractive), observation: CredentialEpisodes{Version: 1, Active: true, Pending: []CredentialEpisode{{ID: "00000000-0000-0000-0000-000000000003"}}}}
	n := &recordingNotifier{}
	w := NewCredentialWatcher(p, store, n)
	if w.Sweep(context.Background()) != 0 || len(p.acknowledged) > 0 {
		t.Fatal("unpersisted failure notified/acknowledged")
	}
	store.recordErr = nil
	if w.Sweep(context.Background()) != 1 {
		t.Fatal("lost failure on database recovery")
	}
	if w.Sweep(context.Background()) != 0 {
		t.Fatal("repeated active episode")
	}
}
func TestCredentialEpisodeDoesNotRepeatTimestampAlert(t *testing.T) {
	store := newMemStateStore()
	_ = store.Record(context.Background(), "s1", srcExpired, time.Now())
	p := &episodeProber{fakeProber: oneTargetProber(srcExpired), observation: CredentialEpisodes{Version: 1, Active: true, Pending: []CredentialEpisode{{ID: "00000000-0000-0000-0000-000000000004"}}}}
	n := &recordingNotifier{}
	w := NewCredentialWatcher(p, store, n)
	if w.Sweep(context.Background()) != 0 || len(p.acknowledged) != 1 {
		t.Fatal("repeated existing unhealthy transition")
	}
	p.observation.Pending = []CredentialEpisode{{ID: "00000000-0000-0000-0000-000000000005", AfterRecovery: true}}
	if w.Sweep(context.Background()) != 1 {
		t.Fatal("missed intervening OAuth recovery")
	}
	if n.alerts[0].PreviousSource != srcInteractive {
		t.Fatal("incorrect recovery transition attribution")
	}
}

type failCurrentState struct {
	*memStateStore
	fail bool
}

func (s *failCurrentState) Record(ctx context.Context, id string, src pb.CodeCredentialSource, at time.Time) error {
	if s.fail {
		return errors.New("current-state write failed")
	}
	return s.memStateStore.Record(ctx, id, src, at)
}
func TestCredentialEpisodeCurrentStateWriteFailure(t *testing.T) {
	store := &failCurrentState{memStateStore: newMemStateStore(), fail: true}
	p := &episodeProber{fakeProber: oneTargetProber(srcInteractive), observation: CredentialEpisodes{Version: 1, Active: true, Pending: []CredentialEpisode{{ID: "00000000-0000-0000-0000-000000000006"}}}}
	n := &recordingNotifier{}
	w := NewCredentialWatcher(p, store, n)
	if w.Sweep(context.Background()) != 1 || len(p.acknowledged) > 0 {
		t.Fatal("episode was not durable before failed state/ack")
	}
	store.fail = false
	w = NewCredentialWatcher(p, store, n)
	if w.Sweep(context.Background()) != 0 || len(p.acknowledged) != 1 {
		t.Fatal("restart duplicated/lost episode")
	}
}
