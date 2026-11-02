package server

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/lxc/incus/v7/shared/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #3242: stop/start request an end state; when it already holds the call is a
// no-op success and none of the post-change work runs.

func newIdempotentServer(state string) (*ContainerServer, *incustest.MockBackend, *[]string) {
	mock := incustest.NewMockBackend()
	mock.Containers["alice-container"] = &incus.ContainerInfo{Name: "alice-container", State: state}
	var sets []string
	mock.SetConfigFunc = func(name, key, value string) error {
		sets = append(sets, key)
		return nil
	}
	s := &ContainerServer{manager: container.NewWithBackend(mock), emitter: events.NewEmitter(events.NewBus())}
	return s, mock, &sets
}

func TestStopContainer_AlreadyStoppedIsNoOpSuccess(t *testing.T) {
	s, mock, sets := newIdempotentServer("Stopped")
	stops := 0
	mock.StopContainerFunc = func(string, bool) error { stops++; return errors.New("The instance is already stopped") }

	resp, err := s.StopContainer(testCtx(), &pb.StopContainerRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(resp.Message, "already stopped") {
		t.Errorf("message %q does not name the already-stopped case", resp.Message)
	}
	if stops != 0 {
		t.Errorf("backend stop sent %d times, want 0", stops)
	}
	for _, k := range *sets {
		if k == incus.StoppedAtKey {
			t.Errorf("stopped_at re-stamped on an already-stopped instance")
		}
	}
}

func TestStopContainer_RunningStampsOnce(t *testing.T) {
	s, _, sets := newIdempotentServer("Running")
	resp, err := s.StopContainer(testCtx(), &pb.StopContainerRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(resp.Message, "stopped successfully") {
		t.Errorf("message = %q", resp.Message)
	}
	n := 0
	for _, k := range *sets {
		if k == incus.StoppedAtKey {
			n++
		}
	}
	if n != 1 {
		t.Errorf("stopped_at stamped %d times, want 1", n)
	}
}

// Two callers race: the loser's backend stop fails with "already stopped" and
// the instance is Stopped on re-read. Both get success.
func TestStopContainer_RaceReturnsSuccess(t *testing.T) {
	s, mock, _ := newIdempotentServer("Running")
	mock.StopContainerFunc = func(name string, _ bool) error {
		mock.Containers[name].State = "Stopped"
		return errors.New("The instance is already stopped")
	}
	if _, err := s.StopContainer(testCtx(), &pb.StopContainerRequest{Username: "alice"}); err != nil {
		t.Fatalf("racing stop must succeed, got %v", err)
	}
}

func TestStopContainer_GenuineFailureIsInternalNotUnknown(t *testing.T) {
	s, mock, _ := newIdempotentServer("Running")
	mock.StopContainerFunc = func(string, bool) error { return errors.New("zfs busy") }
	_, err := s.StopContainer(testCtx(), &pb.StopContainerRequest{Username: "alice"})
	if got := status.Code(err); got != codes.Internal {
		t.Fatalf("code = %v (%v), want Internal", got, err)
	}
	if !strings.Contains(err.Error(), "zfs busy") {
		t.Errorf("cause lost: %v", err)
	}
}

func TestStopStartContainer_MissingIsNotFound(t *testing.T) {
	s, mock, _ := newIdempotentServer("Running")
	mock.GetContainerFunc = func(string) (*incus.ContainerInfo, error) {
		return nil, api.StatusErrorf(http.StatusNotFound, "Instance not found")
	}
	if _, err := s.StopContainer(testCtx(), &pb.StopContainerRequest{Username: "alice"}); status.Code(err) != codes.NotFound {
		t.Errorf("stop code = %v (%v), want NotFound", status.Code(err), err)
	}
	if _, err := s.StartContainer(testCtx(), &pb.StartContainerRequest{Username: "alice"}); status.Code(err) != codes.NotFound {
		t.Errorf("start code = %v (%v), want NotFound", status.Code(err), err)
	}
}

func TestStartContainer_AlreadyRunningIsNoOpSuccess(t *testing.T) {
	s, mock, sets := newIdempotentServer("Running")
	starts := 0
	mock.StartContainerFunc = func(string) error { starts++; return errors.New("The instance is already running") }

	resp, err := s.StartContainer(testCtx(), &pb.StartContainerRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(resp.Message, "already running") {
		t.Errorf("message %q does not name the already-running case", resp.Message)
	}
	if starts != 0 {
		t.Errorf("backend start sent %d times, want 0", starts)
	}
	if len(*sets) != 0 {
		t.Errorf("config writes on a no-op start: %v", *sets)
	}
}

func TestStartContainer_StoppedStartsAndRaceSucceeds(t *testing.T) {
	s, _, sets := newIdempotentServer("Stopped")
	resp, err := s.StartContainer(testCtx(), &pb.StartContainerRequest{Username: "alice"})
	if err != nil || !strings.Contains(resp.Message, "started successfully") {
		t.Fatalf("resp=%v err=%v", resp, err)
	}
	if len(*sets) == 0 {
		t.Errorf("start stamp missing")
	}

	s2, mock2, _ := newIdempotentServer("Stopped")
	mock2.StartContainerFunc = func(name string) error {
		mock2.Containers[name].State = "Running"
		return errors.New("The instance is already running")
	}
	if _, err := s2.StartContainer(testCtx(), &pb.StartContainerRequest{Username: "alice"}); err != nil {
		t.Fatalf("racing start must succeed, got %v", err)
	}
}

func TestStopStartContainer_UnreachableBackendIsUnavailable(t *testing.T) {
	s, mock, _ := newIdempotentServer("Running")
	mock.GetContainerFunc = func(string) (*incus.ContainerInfo, error) { return nil, errors.New("instance not found") }
	pp := NewPeerPool("local-vm", "", nil, "")
	pp.peers["peer-a"] = &PeerClient{ID: "peer-a", Healthy: false}
	s.peerPool = pp

	if _, err := s.StopContainer(testCtx(), &pb.StopContainerRequest{Username: "alice"}); status.Code(err) != codes.Unavailable {
		t.Errorf("stop code = %v (%v), want Unavailable", status.Code(err), err)
	}
	if _, err := s.StartContainer(testCtx(), &pb.StartContainerRequest{Username: "alice"}); status.Code(err) != codes.Unavailable {
		t.Errorf("start code = %v (%v), want Unavailable", status.Code(err), err)
	}
}
