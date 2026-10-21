package server

import (
	"context"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/metrics/platformstats"
	boxlxc "github.com/footprintai/containarium/pkg/core/box/lxc"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type recordingActionReleaser struct {
	mu    sync.Mutex
	boxes []string
}

func (r *recordingActionReleaser) ContainerDeleted(_ context.Context, container string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.boxes = append(r.boxes, container)
}

// TestDeleteContainer_ClosesTheBoxsProcessAction (#2835 item 1): deleting a
// box tells the process responder, so an action open on the deleted box no
// longer holds its finding open or shows as APPLIED.
func TestDeleteContainer_ClosesTheBoxsProcessAction(t *testing.T) {
	const user = "zz2835del" // no such host account: the jump-server cleanup is a no-op
	mock := incustest.NewMockBackend()
	mock.Containers[user+"-container"] = &incus.ContainerInfo{Name: user + "-container", State: "Stopped"}
	mgr := container.NewWithBackend(mock)
	rel := &recordingActionReleaser{}
	s := &ContainerServer{manager: mgr, boxBackend: boxlxc.New(mgr), platformStats: platformstats.New(),
		emitter: events.NewEmitter(events.NewBus()), peerPool: NewPeerPool("local", "", nil, "")}
	s.SetProcessActionReleaser(rel)
	if _, err := s.DeleteContainer(testCtx(), &pb.DeleteContainerRequest{Username: user, Force: true}); err != nil {
		t.Fatalf("DeleteContainer: %v", err)
	}
	if len(rel.boxes) != 1 || rel.boxes[0] != user+"-container" {
		t.Errorf("responder told of deletions %v, want [%s-container]", rel.boxes, user)
	}
}

// A daemon without the sentry wires a nil *ProcessResponder: the setter must
// not store a typed nil that the delete path would then call.
func TestSetProcessActionReleaser_NilResponder(t *testing.T) {
	s := &ContainerServer{}
	var r *ProcessResponder
	s.SetProcessActionReleaser(r)
	s.closeProcessActions(context.Background(), "box-a") // must not panic
}
